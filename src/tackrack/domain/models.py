"""Versioned provider-neutral interchange records and canonical identities."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value: Any) -> str:
    # Collections without semantic ordering must be sorted by callers.
    return digest_bytes(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
    )


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1


class Coverage(Record):
    source_id: str
    capability: str
    status: Literal[
        "complete",
        "partial",
        "not_inspected",
        "permission_denied",
        "unsupported",
        "unavailable",
        "rate_limited",
        "error",
    ]
    reasons: list[str] = Field(default_factory=list)
    result_count: int = 0
    scope: str = "requested scope"


class EvidenceRecord(Record):
    evidence_id: str
    source_id: str
    source_version: str = "0.1.0"
    kind: str
    scope: str = "project"
    revision: str = "working"
    path: str | None = None
    path_bytes: str | None = None
    digest: str
    collected_at: str
    excerpt: str = ""
    sensitivity: str = "ordinary"
    redacted: bool = False
    truncated: bool = False
    byte_start: int = 0
    byte_end: int = 0
    payload: dict[str, Any] = Field(default_factory=dict)


class CollectionResult(Record):
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    coverage: list[Coverage] = Field(default_factory=list)


class SourceDescriptor(Record):
    plugin_id: str
    family: str = "source"
    api_version: int = 1
    plugin_version: str = "0.1.0"
    capabilities: list[str]
    permissions: list[str] = Field(default_factory=list)


class FileEntry(Record):
    path: str
    path_bytes: str
    revision: str
    mode: str
    digest: str | None = None
    object_id: str | None = None
    stage: int = 0
    size: int | None = None
    link_target: str | None = None


class Snapshot(Record):
    root: str
    project_id: str | None = None
    checkout_id: str | None = None
    binding_id: str | None = None
    git_common_dir: str | None = None
    head: str | None = None
    branch: str | None = None
    object_format: str | None = None
    entries: list[FileEntry] = Field(default_factory=list)
    fingerprint: str = ""
    status: Literal["stable", "changed_during_scan", "incomplete"] = "stable"
    reasons: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)
    started_at: str = Field(default_factory=utc_now)
    ended_at: str = Field(default_factory=utc_now)


class Component(Record):
    component_id: str
    scope: str
    path: str
    kind: str
    ownership: str
    disposition: str
    evidence_ids: list[str]
    ownership_spans: list[dict[str, Any]] = Field(default_factory=list)
    consumers: list[str] = Field(default_factory=list)
    configured: str = "yes"
    referenced: str = "unknown"
    observed: str = "unknown"
    enforced: str = "unknown"


class Relationship(Record):
    relationship_id: str
    source_component: str
    target: str
    kind: str
    evidence_ids: list[str]
    confidence: str = "medium"
    unresolved: bool = True


class Finding(Record):
    finding_id: str
    rule_id: str
    rule_version: str = "1"
    title: str
    explanation: str
    severity: Literal["info", "warning", "error", "critical"]
    confidence: str = "high"
    evidence_ids: list[str] = Field(default_factory=list)
    component_ids: list[str] = Field(default_factory=list)
    relationship_ids: list[str] = Field(default_factory=list)
    ownership: str = "unknown"
    disposition: str = "review"
    activity: dict[str, str] = Field(
        default_factory=lambda: {
            "configured": "unknown",
            "referenced": "unknown",
            "observed": "unknown",
            "enforced": "unknown",
        }
    )
    risk: str = ""
    recommended_action: str = "Review evidence before authorising a separate remediation."
    blocking: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class Attachment(Record):
    slot: str
    kind: str = "absent"
    trust: Literal["trusted", "untrusted", "not_present"] = "not_present"
    registered: bool = False
    layout: str | None = None
    independent: bool | None = None
    exclusion_effective: bool | None = None
    snapshot: Snapshot | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Report(Record):
    command: str
    operation_id: str
    status: str = "completed"
    collected_at: str = Field(default_factory=utc_now)
    project: Snapshot
    attachment: Attachment
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    coverage: list[Coverage] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    policy_result: Literal["pass", "fail", "inconclusive"] = "inconclusive"
    coverage_result: Literal["complete", "partial"] = "partial"
    snapshot_status: Literal["current", "historical", "unstable"] = "current"
    verdicts: dict[str, str] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    exit_code: int = 0
