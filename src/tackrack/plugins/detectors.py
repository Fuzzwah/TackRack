"""Pure deterministic detectors. Filenames identify surfaces, not unique harnesses."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable
from typing import Any

import yaml

from tackrack.domain.models import (
    Component,
    EvidenceRecord,
    Finding,
    Relationship,
    canonical_digest,
)
from tackrack.plugins.sources.local_git import active_path

# Declarative development-agent callers, verified against their official repositories.
# https://github.com/anthropics/claude-code-action https://github.com/openai/codex-action
HOSTED_HARNESS_ACTIONS = {"anthropics/claude-code-action", "openai/codex-action"}


class UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.nodes.MappingNode, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ValueError("duplicate_workflow_key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def workflow_harness_actions(text: str) -> list[str]:
    payload = yaml.load(text, Loader=UniqueSafeLoader)
    if not isinstance(payload, dict) or not isinstance(payload.get("jobs", {}), dict):
        raise ValueError("invalid_workflow_jobs")
    uses: list[str] = []
    for job in payload.get("jobs", {}).values():
        if not isinstance(job, dict) or not isinstance(job.get("steps", []), list):
            raise ValueError("invalid_workflow_job")
        if isinstance(job.get("uses"), str):
            uses.append(job["uses"])
        for step in job.get("steps", []):
            if not isinstance(step, dict):
                raise ValueError("invalid_workflow_step")
            if isinstance(step.get("uses"), str):
                uses.append(step["uses"])
    return sorted({use for use in uses if use.split("@", 1)[0].lower() in HOSTED_HARNESS_ACTIONS})


def development_surface(path: str, scope: str) -> bool:
    """Recognise discovery locations, not embedded filename examples in product source."""
    if path.endswith((".template", ".fixture.json")):
        return False
    return (
        active_path(path)
        or path.startswith(
            (".agents/skills/", ".agents/policy/", ".agents/shipping/", ".agents/tools/")
        )
        or path
        in {
            ".agents/project.toml",
            ".agents/tackrack.lock.json",
            ".agents/policy.toml",
            ".agents/shipping.toml",
        }
    )


def surface_consumers(path: str) -> list[str]:
    if posixpath.basename(path) == "AGENTS.md":
        return ["generic agent-instruction consumers"]
    consumers = {
        ".omp": "OMP",
        ".codex": "Codex",
        ".claude": "Claude Code",
        ".cursor": "Cursor",
    }
    first = path.split("/", 1)[0]
    if first in consumers:
        return [consumers[first]]
    if posixpath.basename(path) == "CLAUDE.md":
        return ["Claude Code"]
    if posixpath.basename(path) == "GEMINI.md":
        return ["Gemini CLI"]
    if path == ".cursorrules":
        return ["Cursor"]
    if path == ".mcp.json":
        return ["MCP clients (provider unspecified)"]
    if path.startswith(".github/") or path == "copilot-instructions.md":
        return ["GitHub Copilot"]
    return []


def reference_targets(item: EvidenceRecord, optional_store: bool = False) -> list[str]:
    """Resolve relative links lexically, without accessing any referenced location."""
    targets: set[str] = set()
    optional_store = optional_store or bool(
        re.search(r"--store\b|planningHome\.root|openspec\s+context\b", item.excerpt)
    )
    links = list(re.finditer(r"\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)", item.excerpt))
    for match in links:
        raw = match.group(1).strip("<>").split("#", 1)[0].split("?", 1)[0]
        if not raw or re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", raw) or raw.startswith("//"):
            continue
        if raw.startswith(("/", "~", "\\")):
            targets.add(f"external:{raw}")
            continue
        source = ".agents/" + (item.path or "") if item.scope == "workbench" else item.path or ""
        target = posixpath.normpath(posixpath.join(posixpath.dirname(source), raw))
        if target == ".." or target.startswith("../"):
            targets.add(f"external:{target}")
        elif optional_store and target.startswith("openspec/"):
            targets.add(f"external:{target}")
        else:
            prefix = (
                "workbench"
                if item.scope == "workbench" and target.startswith(".agents/")
                else "project"
            )
            if prefix == "workbench":
                target = target.removeprefix(".agents/")
            targets.add(f"{prefix}:{target}")
    for match in re.finditer(
        r"(?<![A-Za-z0-9_./-])(?:scripts|docs|src|openspec)/[A-Za-z0-9_./-]+",
        item.excerpt,
    ):
        if any(link.start() <= match.start() < link.end() for link in links):
            continue
        target = match.group(0).rstrip(".")
        # Store-aware CLI examples do not assert that the caller owns a local root.
        prefix = "external" if optional_store and target.startswith("openspec/") else "project"
        targets.add(f"{prefix}:{target}")
    return sorted(targets)


class BoundaryDetector:
    plugin_id = "local-boundary"
    plugin_version = "0.1.0"

    def detect(
        self, evidence: Iterable[EvidenceRecord]
    ) -> tuple[list[Component], list[Relationship], list[Finding]]:
        components: list[Component] = []
        relationships: list[Relationship] = []
        findings: list[Finding] = []
        records = sorted(evidence, key=lambda e: e.evidence_id)
        external_store_scopes = {
            (item.scope, item.revision)
            for item in records
            if item.path is not None
            and not item.redacted
            and (
                development_surface(item.path, item.scope)
                or item.scope == "workbench"
                and item.path.startswith(("skills/", "skill-sources/"))
            )
            and re.search(r"(?i)\bopenspec\b", item.path + "\n" + item.excerpt)
            and re.search(r"--store\b|planningHome\.root|openspec\s+context\b", item.excerpt)
        }
        for item in records:
            observation = item.payload.get("observation")
            if isinstance(observation, dict) and observation.get("kind") in {
                "workflow_run",
                "workflow_definition",
            }:
                name = observation.get("name")
                if isinstance(name, str) and re.search(
                    r"(?i)(?:AI|agent)\s+(?:code\s+)?review|claude code|codex.*review", name
                ):
                    cid = canonical_digest(["hosted_workflow", item.evidence_id])
                    components.append(
                        Component(
                            component_id=cid,
                            scope="hosting",
                            path=name,
                            kind="declared_ai_workflow",
                            ownership="unknown",
                            disposition="review",
                            evidence_ids=[item.evidence_id],
                            configured="yes"
                            if observation.get("kind") == "workflow_definition"
                            else "unknown",
                            observed="yes"
                            if observation.get("kind") == "workflow_run"
                            else "unknown",
                        )
                    )
                    findings.append(
                        make_finding(
                            "TR-A013",
                            "Workflow name declares an AI-development process",
                            "The provider records an explicitly AI-development-named workflow. Its name is a declaration, not proof of its implementation, current use, or technical enforcement.",
                            "info",
                            [item.evidence_id],
                            component_ids=[cid],
                            confidence="medium",
                        )
                    )
            if item.kind == "git_config" and item.redacted:
                findings.append(
                    make_finding(
                        "TR-A010",
                        "Sensitive Git configuration withheld",
                        "Credential-like Git metadata was withheld. Credentials must not reside in the swappable companion; use external credential resolution.",
                        "error" if item.scope == "workbench" else "warning",
                        [item.evidence_id],
                        ownership="secret",
                    )
                )
            if item.path is None or item.kind != "file":
                continue
            path = item.path
            active = development_surface(path, item.scope)
            bridge_actions: list[str] = []
            if (
                item.scope == "project"
                and path.startswith(".github/workflows/")
                and path.endswith((".yml", ".yaml"))
                and not item.redacted
            ):
                try:
                    if item.truncated:
                        raise ValueError("workflow_excerpt_truncated")
                    bridge_actions = workflow_harness_actions(item.excerpt)
                except (yaml.YAMLError, ValueError, TypeError, RecursionError):
                    findings.append(
                        make_finding(
                            "TR-A009",
                            "Workflow interpretation is incomplete",
                            "The bounded workflow excerpt is truncated, malformed, duplicate-keyed, or uses unsupported YAML semantics. No absence of development-agent callers is established.",
                            "warning",
                            [item.evidence_id],
                            limitations=[path],
                        )
                    )
            if bridge_actions:
                cid = canonical_digest(["hosted_bridge", item.evidence_id])
                components.append(
                    Component(
                        component_id=cid,
                        scope="project",
                        path=path,
                        kind="hosted_bridge",
                        ownership="harness_implementation",
                        disposition="bridge",
                        evidence_ids=[item.evidence_id],
                        consumers=bridge_actions,
                    )
                )
                findings.append(
                    make_finding(
                        "TR-A001" if item.revision == "index" else "TR-A007",
                        "Development-agent hosting entry point requires an approved bridge",
                        "A workflow declares a known development-agent Action. Tracked bridges are denied by built-in policy; working/historical declarations are separate evidence, not execution or enforcement proof.",
                        "error" if item.revision == "index" else "warning",
                        [item.evidence_id],
                        component_ids=[cid],
                        ownership="harness_implementation",
                        disposition="bridge",
                    )
                )
            inert_test_data = (
                not active
                and item.scope == "project"
                and (
                    path.endswith(".fixture.json")
                    or (path.startswith("tests/") and path.endswith(".py"))
                )
            )
            profile = (item.scope == "workbench" and path.startswith("profiles/")) or (
                item.scope == "project" and path.startswith(".agents/profiles/")
            )
            if profile:
                ownership = "harness_implementation"
            elif item.scope == "workbench" or path.startswith(".agents/"):
                authored_path = path.removeprefix(".agents/") if item.scope == "project" else path
                ownership = (
                    "project_binding"
                    if authored_path in {"project.toml", "tackrack.lock.json"}
                    else "workflow_policy"
                    if authored_path.startswith(("policy/", "shipping/"))
                    or authored_path in {"policy.toml", "shipping.toml"}
                    else "harness_implementation"
                    if active
                    or authored_path.startswith(
                        ("skills/", "skill-sources/", "tools/", "bootstrap/")
                    )
                    else "project_knowledge"
                )
            else:
                ownership = "harness_implementation" if active else "project_capability"
            if path.startswith(("docs/", "openspec/", "specs/")) and not active:
                ownership = "project_knowledge"
            if item.redacted and not inert_test_data:
                ownership = "secret"
            if not active and not profile and item.scope == "project" and not item.redacted:
                # Ordinary runtime prompts and tooling implementations stay product-owned.
                continue
            consumers = surface_consumers(path)
            cid = canonical_digest(
                [
                    item.scope,
                    item.path_bytes or item.path,
                    item.revision,
                    item.payload.get("stage", 0),
                ]
            )
            component = Component(
                component_id=cid,
                scope=item.scope,
                path=path,
                kind="profile_source"
                if profile
                else "instruction_surface"
                if active
                else "companion_source"
                if item.scope == "workbench"
                else "product_source",
                ownership=ownership,
                disposition="review"
                if item.redacted or item.truncated or profile
                else "split"
                if posixpath.basename(path) == "AGENTS.md"
                else "move"
                if ownership == "harness_implementation"
                else "keep",
                evidence_ids=[item.evidence_id],
                consumers=consumers,
                configured="yes" if item.revision == "working" and not profile else "unknown",
            )
            components.append(component)
            if active and item.scope == "project" and item.revision == "working":
                findings.append(
                    make_finding(
                        "TR-A019",
                        "Live harness discovery surface outside attachment",
                        f"{path!r} is a working-tree discovery surface under contained policy, whether ignored or tracked. "
                        "Potential consumption is configured; execution/loading is not established.",
                        "error",
                        [item.evidence_id],
                        ownership=ownership,
                        component_ids=[cid],
                    )
                )
            if active and item.scope == "project" and item.revision == "index":
                findings.append(
                    make_finding(
                        "TR-A001",
                        "Product index owns harness configuration",
                        f"Index owns {path!r}; move/split needs separate reviewed extraction.",
                        "error",
                        [item.evidence_id],
                        ownership=ownership,
                        component_ids=[cid],
                    )
                )
            if item.redacted:
                findings.append(
                    make_finding(
                        "TR-A010",
                        "Redacted inert test data"
                        if inert_test_data
                        else "Sensitive content withheld",
                        "Credential-like content was withheld. Test source/fixture data is product-owned, not an active harness; review before sharing. No extraction is authorised."
                        if inert_test_data
                        else "A probable credential/sensitive file is present. Its payload and content digest were withheld.",
                        "info" if inert_test_data else "error",
                        [item.evidence_id],
                        ownership="project_capability" if inert_test_data else "secret",
                        component_ids=[cid],
                    )
                )
                continue
            if (
                item.scope == "workbench"
                and path.startswith("profiles/")
                and (path.endswith("/SKILL.md") or active)
            ):
                findings.append(
                    make_finding(
                        "TR-A020",
                        "Profile source contains live discovery filename",
                        "Canonical profile payloads should be inert; discovery for this path/version is unverified.",
                        "warning",
                        [item.evidence_id],
                        component_ids=[cid],
                    )
                )
            if item.excerpt and (active or ownership == "harness_implementation"):
                knowledge = re.search(
                    r"(?im)^.*(?:architecture|application uses|domain model|event sourcing|"
                    r"gameplay|scoring and persistence|project (?:structure|overview)|"
                    r"runtime|data contracts|repository map).*$",
                    item.excerpt,
                )
                workflow = re.search(
                    r"(?im)^.*(?:reviewed plan|human sign.?off|before completing|/review|"
                    r"/shipit|working conventions|agent|workflow).*$",
                    item.excerpt,
                )
                if knowledge and workflow and posixpath.basename(path) == "AGENTS.md":
                    component.ownership = "mixed"
                    component.disposition = "review" if item.truncated else "split"
                    findings.append(
                        make_finding(
                            "TR-A003",
                            "Mixed instruction document requires span review",
                            "Project knowledge and workflow intent coexist. Preserve knowledge in product; exact span proposal is evidence-backed, not an authorised edit.",
                            "warning",
                            [item.evidence_id],
                            ownership="mixed",
                            component_ids=[cid],
                        )
                    )
                    for match, category in (
                        (knowledge, "project_knowledge"),
                        (workflow, "workflow_policy"),
                    ):
                        begin = item.byte_start + len(item.excerpt[: match.start()].encode("utf-8"))
                        end = item.byte_start + len(item.excerpt[: match.end()].encode("utf-8"))
                        # Only UTF-8 text without lossy replacement yields exact byte spans.
                        if (
                            not item.truncated
                            and "\ufffd" not in item.excerpt
                            and item.payload.get("exact_utf8_excerpt")
                        ):
                            component.ownership_spans.append(
                                {
                                    "byte_start": begin,
                                    "byte_end": end,
                                    "ownership": category,
                                    "disposition": "keep"
                                    if category == "project_knowledge"
                                    else "review",
                                }
                            )
                for target in reference_targets(
                    item, (item.scope, item.revision) in external_store_scopes
                ):
                    rid = canonical_digest([cid, target, "references"])
                    relationships.append(
                        Relationship(
                            relationship_id=rid,
                            source_component=cid,
                            target=target,
                            kind="references",
                            evidence_ids=[item.evidence_id],
                            unresolved=True,
                        )
                    )
        return components, relationships, findings


def make_finding(
    rule: str,
    title: str,
    explanation: str,
    severity: str,
    evidence_ids: list[str],
    **kwargs: object,
) -> Finding:
    return Finding.model_validate(
        {
            "finding_id": canonical_digest([rule, sorted(evidence_ids), title]),
            "rule_id": rule,
            "title": title,
            "explanation": explanation,
            "severity": severity,
            "evidence_ids": evidence_ids,
            "blocking": ["extraction"] if severity in {"error", "critical"} else [],
            **kwargs,
        }
    )
