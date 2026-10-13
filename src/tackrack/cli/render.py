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
        f"Policy **{report.policy_result}**; coverage **{report.coverage_result}**; snapshot **{report.snapshot_status}**.",
        f"Collected: {local_time.isoformat()} ({cell(display_timezone)}); operation: `{report.operation_id}`.",
        "",
        "## Ownership and scope",
        "",
        f"Product root: `{cell(report.project.root)}`; common Git directory: `{cell(report.project.git_common_dir)}`.",
        f"Product HEAD: `{report.project.head or 'no collected HEAD: unborn or unavailable'}`; fingerprint: `{report.project.fingerprint}`.",
        f"Attachment: {report.attachment.kind}, {report.attachment.trust}, registered={report.attachment.registered}.",
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
        "## Inventory",
        "",
        "| Scope / path / revision | Ownership | Disposition | Configured | Referenced | Observed | Enforced |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in report.components:
        lines.append(
            f"| {cell(c.scope + ':' + c.path)} | {c.ownership} | {c.disposition} | {c.configured} | {c.referenced} | {c.observed} | {c.enforced} |"
        )
    if not report.components:
        lines.append(
            "| No development surfaces found in declared scope | — | — | unknown | unknown | unknown | unknown |"
        )
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
    dispositions: dict[str, int] = {}
    for c in report.components:
        dispositions[c.disposition] = dispositions.get(c.disposition, 0) + 1
    lines += [
        f"Disposition counts: {json.dumps(dispositions, sort_keys=True)}. Extraction is not implemented; all changes require separate reviewed operations.",
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
            cell(json.dumps(report.attachment.metadata["profile_assessment"], sort_keys=True)),
            "",
        ]
    lines += ["- " + cell(limit) for limit in report.limitations]
    lines += [
        "",
        "Next: review findings and coverage; approve any remediation separately. No files were repaired, no project checks/harnesses were launched, no remote settings changed.",
        "",
    ]
    return "\n".join(lines)
