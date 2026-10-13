"""Read-only inspection and static audit; mutation of target roots is never offered."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

from tackrack.domain.models import (
    Attachment,
    Coverage,
    EvidenceRecord,
    Report,
    canonical_digest,
    utc_now,
)
from tackrack.infrastructure.git import (
    GitBroker,
    GitError,
    discover_root,
    git_directories,
    validate_companion_metadata,
)
from tackrack.infrastructure.state import Store, user_roots
from tackrack.plugins.contracts import CollectionRequest, SourceContext, SourceProbeRequest
from tackrack.plugins.detectors import BoundaryDetector, make_finding
from tackrack.plugins.manual import ManualAdapter, read_manifest
from tackrack.plugins.sources.github import GitHubSource
from tackrack.plugins.sources.local_git import SnapshotProbe, collect_snapshot

LIMITATIONS = [
    "Static analysis does not prove absence of dynamic dependencies or ambient harness inputs.",
    "Ordinary ignored product files are excluded except declared known discovery paths; ignored nested discovery under unrelated directories may be unseen.",
    "Unregistered companion configuration is untrusted data and cannot waive built-in rules.",
    "No project checks or harnesses are executed by scan/audit. Product independence requires separate current receipts.",
    "Git exclusion is neither secrecy nor execution-security isolation. Same-user processes can bypass advisory workflow guidance.",
    "Automatic extraction, lifecycle enforcement, attachment mutations and real harness integration are not implemented.",
]


def inspected_roots(root: Path, workbench: Path | None = None) -> list[Path]:
    roots = [root]
    try:
        directory, common = git_directories(root)
        roots.extend([directory, common])
    except GitError:
        pass
    if workbench:
        roots.append(workbench)
        try:
            validate_companion_metadata(workbench)
            directory, common = git_directories(workbench)
            roots.extend([directory, common])
        except GitError:
            pass
    return roots


def inspect(
    root: Path,
    store: Store,
    *,
    command: str,
    attachment_mode: str = "auto",
    offline: bool = False,
    sources: str = "auto",
    remote: str | None = None,
    allow_network: bool = False,
    profile: str | None = None,
    include_ignored: bool = False,
) -> Report:
    root = discover_root(root)
    binding = store.by_project(root)
    slot = root / ".agents"
    attachment = Attachment(slot=str(slot))
    workbench: Path | None = None
    if slot.is_symlink():
        attachment.kind = "symlink"
        attachment.trust = "untrusted"
        attachment.independent = False
        attachment.metadata["link_target"] = os.fsencode(os.readlink(slot)).hex()
        attachment.metadata["reason"] = "symlink_attachment_unverified_not_followed"
    elif slot.exists():
        attachment.kind = "directory" if slot.is_dir() else "file"
        attachment.trust = "untrusted"
        if slot.is_dir():
            workbench = slot
        else:
            attachment.independent = False
    if binding:
        registered = Path(binding["workbench_path"])
        if binding["layout"] == "external":
            workbench = registered
            attachment.kind = "external"
        elif registered == slot and not slot.is_symlink():
            workbench = slot
        attachment.registered = True
        attachment.layout = binding["layout"]
        attachment.trust = "trusted" if binding.get("trust_policy") else "untrusted"
    else:
        attachment.layout = "nested" if workbench else None
    user_roots(inspected_roots(root, workbench))
    project_probe = SnapshotProbe(root)
    companion_probe: SnapshotProbe | None = None
    project, collected = collect_snapshot(
        root, include_ignored=include_ignored, probe=project_probe
    )
    project.project_id, project.checkout_id = store.identity(root)
    if binding:
        project.project_id = binding["project_id"]
        project.checkout_id = binding["checkout_id"]
        project.binding_id = binding["attachment_id"]
    report = Report(
        command=command,
        operation_id=str(uuid.uuid4()),
        project=project,
        attachment=attachment,
        evidence=collected.evidence,
        coverage=collected.coverage,
        limitations=list(LIMITATIONS),
    )
    broker: GitBroker | None = None
    try:
        broker = GitBroker(root)
        effective, diagnostic = broker.exclusion()
        attachment.exclusion_effective = effective
        report.evidence.append(
            EvidenceRecord(
                evidence_id=canonical_digest(["attachment_exclusion", diagnostic.hex()]),
                source_id="local-git",
                kind="attachment_exclusion",
                revision="metadata",
                digest=canonical_digest(diagnostic.hex()),
                collected_at=utc_now(),
                payload={"effective": effective, "diagnostic_bytes": diagnostic.hex()},
            )
        )
    except GitError as exc:
        attachment.metadata["git_reason"] = exc.reason
    identity: dict[str, Any] = {
        "kind": attachment.kind,
        "layout": attachment.layout,
        "registered": attachment.registered,
        "trust": attachment.trust,
    }
    if workbench and workbench.is_dir():
        try:
            validate_companion_metadata(workbench)
            companion = GitBroker(workbench)
            # Root must really be a companion repository; inherited parent identity is invalid.
            attachment.independent = companion.common != Path(project.git_common_dir or root)
            if binding and str(companion.common) != binding["workbench_git_common_dir"]:
                attachment.independent = False
                identity["reason"] = "registered_git_identity_changed"
            identity["git_common_dir"] = str(companion.common)
            if (companion.common / "objects/info/alternates").exists():
                attachment.independent = False
                identity["reason"] = "companion_object_alternates_not_supported"
            if attachment.layout == "nested" and (
                companion.directory != workbench / ".git" or companion.common != workbench / ".git"
            ):
                attachment.independent = False
                identity["reason"] = "external_companion_git_directory_not_approved"
        except GitError as exc:
            attachment.independent = False
            identity["reason"] = exc.reason
        if attachment_mode != "none":
            companion_probe = SnapshotProbe(workbench)
            paired, evidence = collect_snapshot(
                workbench,
                "workbench",
                full=attachment_mode == "full",
                git_enabled=attachment.independent is True,
                probe=companion_probe,
            )
            paired.project_id, paired.checkout_id = store.identity(workbench)
            if binding:
                paired.project_id = binding["companion_id"]
                paired.binding_id = binding["attachment_id"]
            attachment.snapshot = paired
            report.evidence.extend(evidence.evidence)
            report.coverage.extend(evidence.coverage)
    attachment.metadata.update(identity)
    attachment_evidence = EvidenceRecord(
        evidence_id=canonical_digest(["attachment_identity", identity]),
        source_id="local-git",
        kind="attachment_identity",
        revision="metadata",
        scope="workbench",
        digest=canonical_digest(identity),
        collected_at=utc_now(),
        payload=identity,
    )
    report.evidence.append(attachment_evidence)
    report.coverage.append(
        Coverage(
            source_id="local-git",
            capability="attachment_boundary",
            status="not_inspected" if attachment_mode == "none" and workbench else "complete",
            reasons=["content_not_requested"] if attachment_mode == "none" and workbench else [],
            scope=f"reserved slot metadata and product index always; companion content={attachment_mode}",
        )
    )
    if broker:
        remotes = broker.remotes()
    else:
        remotes = {}
    selected_url = None
    if remote:
        selected_url = remotes.get(remote)
        if selected_url is None:
            report.errors.append({"reason": "selected_remote_unavailable", "remote": remote})
    elif binding and binding.get("remote_name") in remotes:
        selected_url = remotes[binding["remote_name"]]
    elif len(remotes) == 1:
        selected_url = next(iter(remotes.values()))
    elif len(remotes) > 1:
        report.limitations.append("Multiple remotes: hosting source not guessed; select --remote.")
    github = GitHubSource()
    probe = github.probe(SourceProbeRequest(root=root, remote_url=selected_url))
    enabled = "github" in sources.split(",") or (sources == "auto" and probe.eligible)
    if enabled:
        remote_result = github.collect(
            CollectionRequest(
                root=root,
                remote_url=selected_url,
                offline=offline,
                network_authorized=allow_network,
            ),
            SourceContext(),
        )
        report.evidence.extend(remote_result.evidence)
        report.coverage.extend(remote_result.coverage)
    else:
        report.coverage.append(
            Coverage(
                source_id="github",
                capability="hosting_metadata",
                status="not_inspected",
                reasons=["not_requested_or_ineligible"],
                scope="product remote only; no companion hosting request",
            )
        )
    report.coverage.append(
        Coverage(
            source_id="ambient",
            capability="ambient_configuration",
            status="not_inspected",
            reasons=["explicit_ambient_scope_not_requested"],
        )
    )
    report.components, report.relationships, report.findings = BoundaryDetector().detect(
        report.evidence
    )
    for edge in report.relationships:
        target = edge.target.removeprefix("project:")
        parts = Path(target).parts
        if ".." in parts or Path(target).is_absolute():
            edge.unresolved = True
        else:
            destination = root / target
            has_link = any(
                p.is_symlink()
                for p in (destination, *destination.parents)
                if p != root and p.is_relative_to(root)
            )
            edge.unresolved = has_link or not destination.is_file()
        if edge.unresolved:
            report.findings.append(
                make_finding(
                    "TR-A008",
                    "Unresolved project resource reference",
                    f"{edge.target!r} is absent or outside the permitted root; automatic removal remains blocked.",
                    "warning",
                    edge.evidence_ids,
                    relationship_ids=[edge.relationship_id],
                )
            )
    for item in report.evidence:
        observation = item.payload.get("observation")
        if isinstance(observation, dict) and observation.get("kind") == "workflow_run":
            commit = observation.get("subject_commit")
            if commit and commit != project.head:
                report.findings.append(
                    make_finding(
                        "TR-A015",
                        "Hosted run refers to a different product revision",
                        "The run's subject commit does not match local HEAD (or the local repository is unborn). It is not verification of this working checkout.",
                        "info",
                        [item.evidence_id],
                    )
                )
    leaks = [e for e in report.evidence if e.kind == "index_leak"]
    index_leaks = [e for e in leaks if e.revision == "index"]
    head_leaks = [e for e in leaks if e.revision == "head"]
    for leak in leaks:
        report.findings.append(
            make_finding(
                "TR-A017",
                f"Reserved attachment owned by product {leak.revision}",
                f"{leak.path!r} is in product {leak.revision}. An ignore rule does not untrack content; index and HEAD are separate facts.",
                "error" if leak.revision == "index" else "warning",
                [leak.evidence_id],
            )
        )
    if workbench and attachment.exclusion_effective is not True:
        report.findings.append(
            make_finding(
                "TR-A017",
                "Attachment lacks effective Git exclusion",
                "The exact reserved slot must be ignored independently of the product index check.",
                "error",
                [attachment_evidence.evidence_id],
            )
        )
    if attachment.kind != "absent" and (
        not attachment.registered or attachment.independent is not True
    ):
        report.findings.append(
            make_finding(
                "TR-A018",
                "Attachment identity is unregistered or unsafe",
                "Static companion bytes are untrusted evidence. No tools or policy have been activated.",
                "error" if attachment.independent is False else "warning",
                [attachment_evidence.evidence_id],
            )
        )
    for item in report.evidence:
        if (
            item.scope == "project"
            and item.revision == "working"
            and item.kind == "file"
            and not item.redacted
        ):
            # Dependency signal only in executable/config surfaces; detector/docs/fixtures literals aren't dependencies.
            dependency_surface = item.path and (
                item.path in {"pyproject.toml", "Dockerfile", "Makefile"}
                or item.path.startswith(".github/workflows/")
            )
            if dependency_surface and any(
                s in item.excerpt
                for s in (
                    ".agents/tools",
                    ".agents/requirements",
                    "cd .agents",
                    "working-directory: .agents",
                )
            ):
                report.findings.append(
                    make_finding(
                        "TR-A021",
                        "Product execution depends on companion material",
                        "A build/check/CI surface references executable companion content.",
                        "error",
                        [item.evidence_id],
                    )
                )
    profile_status = "not_assessed"
    if attachment.trust == "trusted" and workbench and attachment_mode != "none":
        try:
            manifest = read_manifest(workbench)
            if binding and (
                str(manifest.project_id) != binding["project_id"]
                or str(manifest.companion_id) != binding["companion_id"]
            ):
                raise ValueError("registered_manifest_identity_changed")
            if binding and canonical_digest(manifest.model_dump(mode="json")) != binding.get(
                "manifest_digest"
            ):
                raise ValueError("trusted_manifest_changed_requires_review")
            assessment = ManualAdapter().assess(
                root, workbench, profile or manifest.default_profile
            )
            attachment.metadata["profile_assessment"] = assessment
            profile_status = "pass" if assessment["status"] == "compatible" else "inconclusive"
            if profile_status != "pass":
                report.findings.append(
                    make_finding(
                        "TR-A006",
                        "Selected profile is unsupported or unverified",
                        json.dumps(assessment, sort_keys=True),
                        "warning",
                        [attachment_evidence.evidence_id],
                    )
                )
        except (ValueError, OSError) as exc:
            profile_status = "fail"
            report.findings.append(
                make_finding(
                    "TR-A008",
                    "Trusted manifest/resource validation failed",
                    str(exc).split("\n")[0][:200],
                    "error",
                    [attachment_evidence.evidence_id],
                )
            )
    probes = [(project, project_probe)]
    if attachment.snapshot and companion_probe:
        probes.append((attachment.snapshot, companion_probe))
    for snapshot, witness in probes:
        if witness.changed():
            snapshot.status = "changed_during_scan"
            snapshot.reasons = sorted(set(snapshot.reasons + ["changed_during_scan"]))
            namespace = snapshot.scope["namespace"]
            for coverage in report.coverage:
                if coverage.source_id == "local-git" and coverage.scope.startswith(namespace + ":"):
                    coverage.status = "partial"
                    coverage.reasons = sorted(set(coverage.reasons + ["changed_during_scan"]))
        snapshot.ended_at = utc_now()
    local_partial = any(
        c.source_id == "local-git" and c.status in {"partial", "error", "unavailable"}
        for c in report.coverage
    )
    workflow_gaps = [f for f in report.findings if f.rule_id == "TR-A009"]
    if workflow_gaps:
        local_partial = True
        report.coverage.append(
            Coverage(
                source_id="local-boundary",
                capability="workflow_interpretation",
                status="partial",
                reasons=["bounded_or_ambiguous_workflow"],
                scope="declared product workflow evidence",
                result_count=len(workflow_gaps),
            )
        )
    unstable = project.status == "changed_during_scan" or (
        attachment.snapshot and attachment.snapshot.status == "changed_during_scan"
    )
    for c in report.coverage:
        if c.source_id == "local-git" and c.status == "partial":
            report.findings.append(
                make_finding(
                    "TR-A009",
                    "Required local coverage is incomplete",
                    "; ".join(c.reasons),
                    "warning",
                    [],
                    limitations=[c.scope],
                )
            )
    fail = any(f.severity in {"error", "critical"} for f in report.findings)
    unassessed_required = bool(profile) and profile_status != "pass"
    report.policy_result = (
        "fail"
        if fail
        else "inconclusive"
        if local_partial or unstable or unassessed_required
        else "pass"
    )
    report.coverage_result = (
        "partial" if any(c.status != "complete" for c in report.coverage) else "complete"
    )
    report.snapshot_status = "unstable" if unstable else "current"
    report.verdicts = {
        "product_git_boundary": "fail"
        if index_leaks
        or any(f.rule_id == "TR-A001" and f.severity == "error" for f in report.findings)
        else "inconclusive"
        if broker is None
        else "pass",
        "committed_boundary": "fail" if head_leaks else "pass" if broker else "inconclusive",
        "local_containment": "fail"
        if any(f.rule_id == "TR-A019" for f in report.findings)
        else "inconclusive"
        if local_partial
        else "pass",
        "profile_configuration": profile_status,
        "product_independence": "not_verified",
        "attachment_trust": attachment.trust,
    }
    report.exit_code = (
        4 if unstable else 1 if fail else 3 if report.policy_result == "inconclusive" else 0
    )
    if report.errors:
        report.exit_code = 2
    report.evidence.sort(key=lambda e: e.evidence_id)
    report.findings.sort(
        key=lambda f: (
            {"critical": 0, "error": 1, "warning": 2, "info": 3}[f.severity],
            f.rule_id,
            f.finding_id,
        )
    )
    report.coverage.sort(key=lambda c: (c.source_id, c.capability, c.scope))
    return report


def register(
    name: str,
    project: Path,
    workbench: Path,
    store: Store,
    *,
    trust_policy: bool = False,
    remote_name: str | None = None,
) -> dict[str, Any]:
    project = discover_root(project)
    if workbench.is_symlink():
        raise ValueError("symlink_attachment_not_supported")
    workbench = workbench.resolve(strict=True)
    slot = project / ".agents"
    layout = "nested" if workbench == slot else "external"
    if layout == "external" and (
        workbench.is_relative_to(project) or project.is_relative_to(workbench)
    ):
        raise ValueError("overlapping_product_and_companion_roots")
    user_roots(inspected_roots(project, workbench))
    validate_companion_metadata(workbench)
    product_git, companion_git = GitBroker(project), GitBroker(workbench)
    if (companion_git.common / "objects/info/alternates").exists():
        raise ValueError("companion_object_alternates_not_supported")
    if product_git.common == companion_git.common:
        raise ValueError("shared_git_identity")
    if layout == "nested" and (
        companion_git.directory != workbench / ".git" or companion_git.common != workbench / ".git"
    ):
        raise ValueError("unapproved_external_companion_git_metadata")
    if layout == "nested" and not product_git.exclusion()[0]:
        raise ValueError("effective_attachment_exclusion_required")
    for row in product_git.run("ls-files", "--stage", "-z").split(b"\x00"):
        if row and (
            row.split(b"\t", 1)[1] == b".agents" or row.split(b"\t", 1)[1].startswith(b".agents/")
        ):
            raise ValueError("product_index_attachment_leak")
    manifest = read_manifest(workbench)
    existing = store.binding(name)
    record: dict[str, Any] = {
        "schema_version": 1,
        "name": name,
        "project_id": str(manifest.project_id),
        "companion_id": str(manifest.companion_id),
        "checkout_id": existing["checkout_id"] if existing else str(uuid.uuid4()),
        "attachment_id": existing["attachment_id"] if existing else str(uuid.uuid4()),
        "project_path": str(project),
        "workbench_path": str(workbench),
        "layout": layout,
        "project_git_common_dir": str(product_git.common),
        "workbench_git_common_dir": str(companion_git.common),
        "manifest_digest": canonical_digest(manifest.model_dump(mode="json")),
        "trust_policy": trust_policy,
        "remote_name": remote_name,
        "network_sources_enabled": [],
        "timezone": "Australia/Hobart",
        "lifecycle_state": "attached_inactive",
    }
    return store.register(name, record)
