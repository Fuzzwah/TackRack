"""One report model, terminal/Markdown renderers; repository strings remain data."""

from __future__ import annotations

import html
import json
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from tackrack.domain.models import Report
from tackrack.infrastructure.redaction import sanitize


def cell(value: object) -> str:
    text, _ = sanitize(str(value))
    return html.escape(text).replace("|", "\\|").replace("\n", " ")


def markdown(report: Report, *, display_timezone: str = "UTC") -> str:
    try:
        local_time = datetime.fromisoformat(report.collected_at).astimezone(
            ZoneInfo(display_timezone)
        )
    except (ValueError, ZoneInfoNotFoundError):
        raise ValueError("invalid_display_timezone") from None
    lines = [
        f"# TackRack {report.command}",
        "",
        (
            f"Discovery completed; separation policy **not assessed**; coverage **{report.coverage_result}**; snapshot **{report.snapshot_status}**."
            if report.command == "scan"
            else f"Policy **{report.policy_result}**; coverage **{report.coverage_result}**; snapshot **{report.snapshot_status}**."
        ),
        f"Collected: {local_time.isoformat()} ({cell(display_timezone)}); operation: `{report.operation_id}`.",
        "",
        "## Detected AI development tooling",
        "",
    ]
    for location, heading in (
        ("local", "Local harnesses and workflow"),
        ("hosted", "Hosted integrations"),
    ):
        lines += [
            f"### {heading}",
            "",
            "| Tool / workflow | State | Evidence paths | Configured | Observed | Enforced |",
            "|---|---|---|---|---|---|",
        ]
        tools = [tool for tool in report.tooling if tool.location == location]
        for tool in tools:
            paths = ", ".join(tool.paths)
            lines.append(
                f"| {cell(tool.name)} ({cell(tool.scope)}) | {cell(tool.state)} | {cell(paths)} | {cell(tool.configured)} | {cell(tool.observed)} | {cell(tool.enforced)} |"
            )
        if not tools:
            if location == "hosted" and any(
                c.source_id == "github" and c.status != "complete" for c in report.coverage
            ):
                lines.append(
                    "Hosting evidence is unassessed/incomplete; no absence of remote AI tooling is established."
                )
            else:
                lines.append(
                    "No tooling identified by the current catalogue in the declared scope; not a universal absence claim."
                )
        lines += [""]
        limits = sorted({limit for tool in tools for limit in tool.limitations})
        lines += [f"- {cell(limit)}" for limit in limits]
        if tools:
            lines += [""]
    lines += [
        "## Ownership and scope",
        "",
        f"Product root: `{cell(report.project.root)}`; common Git directory: `{cell(report.project.git_common_dir)}`.",
        f"Product HEAD: `{report.project.head or 'no collected HEAD: unborn or unavailable'}`; fingerprint: `{report.project.fingerprint}`.",
        f"Attachment slot: {report.attachment.kind}; role **{report.attachment.slot_role}**; {report.attachment.trust}; registered={report.attachment.registered}.",
        f"Exclusion effective: {report.attachment.exclusion_effective}; independence: {report.attachment.independent}.",
    ]
    if report.attachment.snapshot:
        snap = report.attachment.snapshot
        lines += [
            f"Companion common Git directory: `{cell(snap.git_common_dir)}`; HEAD: `{snap.head or 'no collected HEAD: unborn or unavailable'}`.",
            f"Companion fingerprint: `{snap.fingerprint}`.",
        ]
    lines += ["", "| Verdict | Result |", "|---|---|"]
    lines += [f"| {cell(k)} | {cell(v)} |" for k, v in sorted(report.verdicts.items())]
    lines += [
        "",
        "## Ownership and extraction candidates",
        "",
        "| Scope / path | Revisions | Ownership | Proposed disposition | Review / blockers |",
        "|---|---|---|---|---|",
    ]
    for item in report.extraction.items:
        lines.append(
            f"| {cell(item.scope + ':' + item.path)} | {cell(', '.join(item.revisions))} | {cell(item.ownership)} | {item.disposition} | {cell('; '.join(item.blockers) or item.explanation)} |"
        )
    if not report.extraction.items:
        lines.append("No extraction candidates identified within the declared scope.")
    lines += [
        "",
        "## Coverage",
        "",
        "| Source / capability | Status | Count | Scope / reasons |",
        "|---|---|---|---|",
    ]
    for coverage in report.coverage:
        lines.append(
            f"| {cell(coverage.source_id + '/' + coverage.capability)} | {coverage.status} | {coverage.result_count} | {cell(coverage.scope + '; ' + ', '.join(coverage.reasons))} |"
        )
    lines += ["", "## Findings", ""]
    for f in report.findings:
        lines += [
            f"### {f.rule_id}: {cell(f.title)} ({f.severity}, {f.confidence})",
            "",
            cell(f.explanation),
            "",
            "Evidence: " + ", ".join(f"`{e}`" for e in f.evidence_ids),
            "",
            "Recommendation (not performed): " + cell(f.recommended_action),
            "",
        ]
    if not report.findings:
        lines += [
            "No findings within the declared scope. This is not a universal absence claim.",
            "",
        ]
    lines += ["## Relationships and extraction readiness", ""]
    for r in report.relationships:
        lines.append(
            f"- {r.kind}: `{r.source_component}` → `{cell(r.target)}`; unresolved={r.unresolved}; evidence={','.join(r.evidence_ids)}."
        )
    lines += [
        f"Extraction readiness: **{report.extraction.status}**. This is an inventory for review, not an executable plan or proof of equivalent relocated behavior.",
        "",
    ]
    lines += ["- Blocker: " + cell(reason) for reason in report.extraction.blockers]
    lines += ["- Limit: " + cell(reason) for reason in report.extraction.limitations]
    lines += [
        "Extraction is not implemented. Preserve project knowledge, shared checks and existing .agents bytes; no move, index cleanup or adoption is performed.",
        "",
        "## Evidence",
        "",
    ]
    for e in report.evidence:
        lines.append(
            f"- `{e.evidence_id}` {cell(e.scope)} / {cell(e.path or e.kind)} / {cell(e.revision)}; bytes [{e.byte_start},{e.byte_end}); digest `{e.digest}`; redacted={e.redacted}; truncated={e.truncated}."
        )
    lines += ["", "## Compatibility, limits, and next actions", ""]
    if "profile_assessment" in report.attachment.metadata:
        lines += [
            "```json\n"
            + json.dumps(report.attachment.metadata["profile_assessment"], sort_keys=True, indent=2)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            + "\n```",
            "",
        ]
    lines += ["- " + cell(limit) for limit in report.limitations]
    lines += [
        "",
        "Next: review findings and coverage; approve any remediation separately. No files were repaired, no project checks/harnesses were launched, no remote settings changed.",
        "",
    ]
    return "\n".join(lines)
