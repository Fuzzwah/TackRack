"""Pure evidence reconciliation for read-only tooling and extraction review."""

from __future__ import annotations

import posixpath
import re
import tomllib
from collections import defaultdict
from typing import Literal

from tackrack.domain.models import (
    Component,
    EvidenceRecord,
    ExtractionItem,
    ExtractionReadiness,
    Report,
    ToolInventory,
    canonical_digest,
)
from tackrack.plugins.detectors import development_surface, surface_consumers


def _profile(item: EvidenceRecord) -> tuple[str, str] | None:
    path = item.path or ""
    prefix = ".agents/" if item.scope == "project" else ""
    if not path.startswith(prefix + "profiles/"):
        return None
    parts = path[len(prefix) :].split("/")
    if len(parts) < 3:
        return None
    name = parts[1]
    state = "declared"
    if path.endswith("/profile.toml") and not item.redacted and not item.truncated:
        try:
            config = tomllib.loads(item.excerpt)
        except (tomllib.TOMLDecodeError, ValueError):
            return name, "unverified"
        if config.get("enabled") is False:
            state = "disabled"
        elif config.get("adapter") == "manual" or config.get("render_strategy") == "manual":
            state = "manual"
    return name, state


def _families(item: EvidenceRecord) -> list[tuple[str, str, str]]:
    path = item.path or ""
    profile = _profile(item)
    if profile:
        return [(profile[0], "intended_profile", profile[1])]
    if (
        (
            (item.scope == "workbench" and path == "project.toml")
            or (item.scope == "project" and path == ".agents/project.toml")
        )
        and not item.redacted
        and not item.truncated
    ):
        try:
            manifest = tomllib.loads(item.excerpt)
        except (tomllib.TOMLDecodeError, ValueError):
            return []
        selected = manifest.get("default_profile")
        if isinstance(selected, str) and selected:
            return [(selected, "intended_profile", "declared")]
    active = development_surface(path, item.scope)
    companion_skill = item.scope == "workbench" and path.startswith(("skills/", "skill-sources/"))
    families: list[tuple[str, str, str]] = []
    if active:
        consumers = surface_consumers(path)
        for consumer in consumers:
            families.append(
                (
                    "Generic agent instructions"
                    if consumer == "generic agent-instruction consumers"
                    else consumer,
                    "agent_instructions"
                    if consumer == "generic agent-instruction consumers"
                    else "development_harness",
                    "present",
                )
            )
        if path.startswith(".agents/skills/"):
            families.append(("Shared agent skills", "shared_skills", "present"))
    if companion_skill:
        families.append(("Shared agent skills", "shared_skills", "present"))
    if (active or companion_skill) and re.search(r"(?:^|/)(?:shipit|shipping)(?:/|\.)", path):
        families.append(("Shipping workflow", "shipping_workflow", "present"))
    if item.scope == "workbench" and (path.startswith("shipping/") or path == "shipping.toml"):
        families.append(("Shipping workflow", "shipping_workflow", "present"))
    if (
        (active or companion_skill)
        and not item.redacted
        and (re.search(r"(?i)\bopenspec\b|/opsx[-:]", item.excerpt) or "openspec" in path)
    ) or (item.scope == "project" and path in {"openspec/config.yaml", "openspec/config.yml"}):
        families.append(("OpenSpec", "specification_workflow", "present"))
    return families


def _state(records: list[EvidenceRecord], declarations: list[str]) -> tuple[str, str]:
    current = [record for record in records if record.revision == "working"]
    if current:
        if "disabled" in declarations:
            return "disabled", "no"
        if "manual" in declarations:
            return "manual", "no"
        if "unverified" in declarations or all(record.redacted for record in current):
            return "unverified", "unknown"
        if "declared" in declarations:
            return "declared", "unknown"
        return "configured", "yes"
    if any(record.revision == "index" for record in records):
        return "staged", "unknown"
    return "historical", "unknown"


def _review_item(
    scope: str,
    path: str,
    records: list[EvidenceRecord],
    components: list[Component],
    references: list[str],
    unresolved: list[str],
) -> ExtractionItem:
    current = [record for record in records if record.revision == "working"]
    relevant = current or [record for record in records if record.revision == "index"] or records
    relevant_ids = {record.evidence_id for record in relevant}
    current_components = [
        component for component in components if relevant_ids.intersection(component.evidence_ids)
    ]
    ownerships = {component.ownership for component in current_components}
    ownership = (
        "mixed"
        if "mixed" in ownerships or len(ownerships) > 1
        else next(
            iter(ownerships),
            "project_knowledge"
            if path.startswith(("docs/", "openspec/", "specs/"))
            else "project_capability",
        )
    )
    blockers: list[str] = []
    disposition: Literal["keep", "move", "split", "review"] = "keep"
    explanation = "Preserve product knowledge, resources, checks, and runtime implementation; no harness extraction is inferred from content strings."
    if ownership == "mixed":
        disposition = "split"
        explanation = "Separate reviewed workflow spans from project knowledge; retain product contracts and referenced resources."
    elif ownership == "harness_implementation" and current_components:
        if scope == "workbench":
            explanation = (
                "Harness source is already outside product ownership; retain it in the companion."
            )
        else:
            disposition = "move"
            explanation = "Native harness/skill source is an extraction candidate, subject to explicit ownership and destination review; no move is authorised."
    elif ownership == "secret":
        disposition = "review"
        explanation = "Sensitive source is withheld; preserve it and review ownership/credential handling before proposing extraction."
    elif ownership in {"workflow_policy", "project_binding"}:
        if scope == "project":
            disposition = "move"
            explanation = "Embedded workflow policy/binding is a companion candidate; preserve bytes and review its consumers before relocation."
        else:
            explanation = "Independent companion policy/binding remains distinct from replaceable harness implementation."
    if any(
        component.kind in {"profile_source", "hosted_bridge"} for component in current_components
    ):
        disposition = "review"
        explanation = "Declared profiles and hosted entry points require activation/bridge review; source presence is not an installed or active harness."
    if (
        any(posixpath.basename(record.path or "") == "AGENTS.md" for record in relevant)
        and disposition == "move"
    ):
        disposition = "review"
        explanation = "Generic agent instructions do not establish a unique provider or harness-only ownership; review knowledge and workflow boundaries."
    # Excluded/truncated ordinary product bytes do not turn product assets/specifications into harness candidates.
    if disposition == "keep":
        return ExtractionItem(
            scope=scope,
            path=path,
            ownership=ownership,
            disposition="keep",
            revisions=sorted({record.revision for record in records}),
            evidence_ids=sorted({record.evidence_id for record in records}),
            component_ids=sorted({component.component_id for component in components}),
            references=sorted(set(references)),
            explanation=explanation,
        )
    if any(record.redacted for record in relevant):
        blockers.append(
            "Sensitive content withheld; ownership and safe extraction cannot be established."
        )
    if any(record.truncated for record in relevant):
        blockers.append(
            "Truncated source requires complete authorised content review before extraction."
        )
    if any(
        record.payload.get("mode") in {"120000", "160000"} or record.payload.get("stage", 0) != 0
        for record in relevant
    ):
        blockers.append(
            "Unsafe or conflicted file identity requires review without following its target."
        )
    if unresolved:
        blockers.append(
            "Unresolved references require review: " + ", ".join(sorted(set(unresolved)))
        )
    if blockers:
        disposition = "review"
    if not current:
        disposition = "review"
        blockers.append(
            "No current working source was observed; staged/historical evidence is not a live installation."
        )
    return ExtractionItem(
        scope=scope,
        path=path,
        ownership=ownership,
        disposition=disposition,
        revisions=sorted({record.revision for record in records}),
        evidence_ids=sorted({record.evidence_id for record in records}),
        component_ids=sorted({component.component_id for component in components}),
        references=sorted(set(references)),
        blockers=blockers,
        explanation=explanation,
    )


def build_inventory(report: Report) -> tuple[list[ToolInventory], ExtractionReadiness]:
    """Aggregate physical inputs across revisions; never access a target or execute tooling."""
    files: dict[tuple[str, str], list[EvidenceRecord]] = defaultdict(list)
    groups: dict[tuple[str, str, str], list[tuple[EvidenceRecord, str]]] = defaultdict(list)
    for item in report.evidence:
        if item.kind != "file" or item.path is None:
            continue
        files[item.scope, item.path].append(item)
        for name, kind, state in _families(item):
            groups[item.scope, name, kind].append((item, state))
    evidence_by_id = {item.evidence_id: item for item in report.evidence}
    for component in report.components:
        if component.kind != "hosted_bridge":
            continue
        for consumer in component.consumers:
            name = consumer.split("@", 1)[0]
            for evidence_id in component.evidence_ids:
                action_evidence = evidence_by_id.get(evidence_id)
                if action_evidence is not None:
                    groups[component.scope, name, "hosted_agent_action"].append(
                        (action_evidence, "present")
                    )
    tooling: list[ToolInventory] = []
    for (scope, name, kind), entries in sorted(groups.items()):
        records = list({item.evidence_id: item for item, _ in entries}.values())
        latest = [state for item, state in entries if item.revision == "working"]
        state, configured = _state(records, latest)
        tooling.append(
            ToolInventory(
                tool_id=canonical_digest([scope, name, kind]),
                name=name,
                kind=kind,
                location="hosted" if kind == "hosted_agent_action" else "local",
                scope=scope,
                state=state,
                paths=sorted({item.path for item in records if item.path is not None}),
                revisions=sorted({item.revision for item in records}),
                evidence_ids=sorted({item.evidence_id for item in records}),
                configured=configured,
                limitations=[
                    "Static declarations establish potential consumption only, not installation, execution, loading, or enforcement."
                ],
            )
        )
    # Hosted observations are separate from local files and retain their original evidence.
    hosted: dict[str, list[Component]] = defaultdict(list)
    for component in report.components:
        if component.scope == "hosting":
            hosted[component.path].append(component)
    for path, components in sorted(hosted.items()):
        observed = (
            "yes" if any(component.observed == "yes" for component in components) else "unknown"
        )
        configured = (
            "yes" if any(component.configured == "yes" for component in components) else "unknown"
        )
        tooling.append(
            ToolInventory(
                tool_id=canonical_digest(["hosting", path]),
                name=path,
                kind="hosted_workflow",
                location="hosted",
                scope="hosting",
                state="observed" if observed == "yes" else "declared",
                paths=[path],
                evidence_ids=sorted(
                    {eid for component in components for eid in component.evidence_ids}
                ),
                configured=configured,
                observed=observed,
                confidence="medium",
                limitations=["Workflow names do not identify a provider or prove implementation."],
            )
        )
    components_by_path: dict[tuple[str, str], list[Component]] = defaultdict(list)
    for component in report.components:
        components_by_path[component.scope, component.path].append(component)
    items: list[ExtractionItem] = []
    external_stores = any(
        name == "OpenSpec"
        and item.revision == "working"
        and re.search(r"--store\b|planningHome\.root|openspec\s+context\b", item.excerpt)
        for (_, name, _), entries in groups.items()
        for item, _ in entries
    )
    for (scope, path), records in sorted(files.items()):
        components = components_by_path[scope, path]
        ids = {component.component_id for component in components}
        relations = [
            relation for relation in report.relationships if relation.source_component in ids
        ]
        relevant_ids = {item.evidence_id for item in records if item.revision == "working"}
        current_relations = [
            relation
            for relation in relations
            if not relevant_ids or relevant_ids.intersection(relation.evidence_ids)
        ]
        external_stores |= any(
            relation.target.startswith("external:openspec/") for relation in current_relations
        )
        items.append(
            _review_item(
                scope,
                path,
                records,
                components,
                [relation.target for relation in relations],
                [
                    relation.target
                    for relation in current_relations
                    if relation.unresolved and not relation.target.startswith("external:")
                ],
            )
        )
    blockers: list[str] = []
    if external_stores:
        blockers.append(
            "OpenSpec permits an external store/context root; the selected store and its availability are unknown and must be reviewed. External roots were not accessed."
        )
    if any(item.blockers for item in items):
        blockers.append(
            "Per-file content, identity, revision, or reference blockers require review before extraction."
        )
    if any(
        coverage.status != "complete" and coverage.source_id.startswith("local")
        for coverage in report.coverage
    ):
        blockers.append(
            "Local collection coverage is incomplete; absence of additional extraction inputs is not established."
        )
    candidates = any(item.disposition != "keep" for item in items)
    readiness = ExtractionReadiness(
        status="blocked" if blockers else "review_required" if candidates else "no_candidates",
        items=items,
        blockers=blockers,
        limitations=[
            "Read-only review inventory, not an executable extraction plan or a portability/equivalence proof."
        ],
    )
    return tooling, readiness
