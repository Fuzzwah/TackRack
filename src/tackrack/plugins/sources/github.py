"""Read-only public GitHub summaries; no code, logs, secrets, or PR fetches.

API version 2026-03-10 is explicitly supported by GitHub's published version
policy: https://docs.github.com/en/rest/about-the-rest-api/api-versions.
Ruleset coverage means visible rulesets, not proof of effective branch protection
or integration enforcement. Actions coverage is bounded to the last 30 days.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from tackrack.domain.models import (
    CollectionResult,
    Coverage,
    EvidenceRecord,
    SourceDescriptor,
    canonical_digest,
    utc_now,
)
from tackrack.infrastructure.http import (
    API_ORIGIN,
    API_VERSION,
    CoverageStatus,
    GitHubHTTP,
    HTTPFailure,
)
from tackrack.infrastructure.redaction import sanitize, sensitive_key
from tackrack.plugins.contracts import (
    CollectionRequest,
    SourceContext,
    SourceProbeRequest,
    SourceProbeResult,
)

SOURCE_ID = "github"
CAPABILITIES = (
    "github.repository",
    "github.actions_runs",
    "github.rulesets",
    "github.workflow_definitions",
)
DEFERRED = ("github.pull_requests", "github.integration_policy")
MAX_PAGES = 20
MAX_RECORDS = 1000
MAX_RULESET_DETAILS = 100
_COMPONENT = re.compile(r"[A-Za-z0-9_.-]+\Z")
_SCP = re.compile(r"git@github\.com:([^/]+)/([^/]+)\Z")


def remote_identity(remote: str | None) -> dict[str, str] | None:
    """Static mapping only: no Git commands, DNS, credential reads, or requests."""
    if not remote or len(remote) > 2048 or any(ord(c) < 33 for c in remote):
        return None
    if sanitize(remote)[1]:
        return None
    scp = _SCP.fullmatch(remote)
    if scp:
        owner, repo = scp.groups()
    else:
        try:
            parsed = urlsplit(remote)
            if parsed.query or parsed.fragment or parsed.password or "%" in remote:
                return None
            if parsed.scheme == "https":
                if parsed.netloc != "github.com" or parsed.username is not None:
                    return None
            elif parsed.scheme == "ssh":
                if parsed.netloc != "git@github.com":
                    return None
            else:
                return None
            segments = parsed.path.strip("/").split("/")
            if len(segments) != 2:
                return None
            owner, repo = segments
        except ValueError:
            return None
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not all(_COMPONENT.fullmatch(part) and part not in {".", ".."} for part in (owner, repo)):
        return None
    return {"owner": owner, "repo": repo, "full_name": f"{owner}/{repo}"}


def _coverage(capability: str, status: CoverageStatus, reason: str, count: int = 0) -> Coverage:
    return Coverage(
        source_id=SOURCE_ID,
        capability=capability,
        status=status,
        reasons=[reason],
        result_count=count,
        scope="visible public GitHub API metadata; Actions within requested window",
    )


class GitHubSource:
    def describe(self) -> SourceDescriptor:
        return SourceDescriptor(
            plugin_id=SOURCE_ID,
            capabilities=list(CAPABILITIES),
            permissions=["network:https://api.github.com"],
        )

    def probe(self, request: SourceProbeRequest) -> SourceProbeResult:
        identity = remote_identity(request.remote_url)
        return SourceProbeResult(
            eligible=identity is not None,
            reason="static github.com remote mapping"
            if identity
            else "no supported credential-free github.com remote",
            identity=identity or {},
        )

    def collect(self, request: CollectionRequest, context: SourceContext) -> CollectionResult:
        deferred = [
            _coverage(cap, "unsupported", "deferred; not collected in M0/M1") for cap in DEFERRED
        ]
        identity = remote_identity(request.remote_url)
        if request.offline or not request.network_authorized or identity is None:
            reason = (
                "offline; no network request"
                if request.offline
                else "explicit public GitHub network permission required"
                if not request.network_authorized
                else "no supported credential-free github.com remote"
            )
            return CollectionResult(
                coverage=[_coverage(cap, "not_inspected", reason) for cap in CAPABILITIES]
                + deferred
            )
        collected_at = context.clock() if context.clock is not None else utc_now()
        try:
            now = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
            if now.tzinfo is None:
                raise ValueError
            now = now.astimezone(UTC)
        except (ValueError, TypeError, AttributeError):
            return CollectionResult(
                coverage=[
                    _coverage(cap, "error", "invalid collection clock") for cap in CAPABILITIES
                ]
                + deferred
            )
        days = max(1, min(30, request.window_days))
        start = now - timedelta(days=days)
        created_filter = f"{start.isoformat()}..{now.isoformat()}"
        token = os.environ.get("TACKRACK_GITHUB_TOKEN") or None
        # Invalid header text is never sent and never echoed.
        if token and (len(token) > 4096 or not all(33 <= ord(c) <= 126 for c in token)):
            return CollectionResult(
                coverage=[
                    _coverage(cap, "error", "invalid explicitly named GitHub token")
                    for cap in CAPABILITIES
                ]
                + deferred
            )
        collector = _Collector(
            GitHubHTTP(context.http, token),
            token,
            identity,
            collected_at,
            max(1, min(MAX_PAGES, request.max_pages)),
            max(1, min(MAX_RECORDS, request.max_records)),
        )
        try:
            collector.repository()
            collector.actions(created_filter, start, now)
            collector.rulesets()
            collector.workflows()
            return CollectionResult(
                evidence=collector.evidence, coverage=collector.coverage + deferred
            )
        finally:
            collector.http.close()


class _Collector:
    def __init__(
        self,
        http: GitHubHTTP,
        token: str | None,
        identity: dict[str, str],
        collected_at: str,
        max_pages: int,
        max_records: int,
    ) -> None:
        self.http = http
        self.token = token
        self.identity = identity
        self.collected_at = collected_at
        self.max_pages = max_pages
        self.max_records = max_records
        self.base = f"/repos/{identity['owner']}/{identity['repo']}"
        self.evidence: list[EvidenceRecord] = []
        self.coverage: list[Coverage] = []
        self.default_branch: str | None = None

    def _record(self, kind: str, endpoint: str, body_digest: str, data: dict[str, Any]) -> None:
        clean, redacted, truncated = _clean(data, self.token)
        redacted |= body_digest == "withheld-sensitive-response"
        endpoint_clean, endpoint_redacted, endpoint_cut = _clean(endpoint, self.token)
        scope, scope_redacted, scope_cut = _clean(self.identity["full_name"], self.token)
        redacted |= endpoint_redacted or scope_redacted
        truncated |= endpoint_cut or scope_cut
        payload = {
            "data": clean,
            "provenance": {
                "endpoint": endpoint_clean,
                "origin": API_ORIGIN,
                "api_version": API_VERSION,
                "response_digest": "withheld-sensitive-response" if redacted else body_digest,
                "collection": "live-api",
            },
        }
        if kind in {"github.actions_run", "github.workflow_definition"}:
            payload["observation"] = {
                "kind": "workflow_run" if kind == "github.actions_run" else "workflow_definition",
                "subject_commit": clean.get("head_sha"),
                "ref": clean.get("head_branch") or clean.get("default_branch"),
                "name": clean.get("name"),
                "path": clean.get("path"),
                "event_time": clean.get("created_at"),
            }
        digest = canonical_digest(payload)
        revision = clean.get("head_sha") or clean.get("default_branch") or "remote"
        self.evidence.append(
            EvidenceRecord(
                evidence_id=f"github:{kind}:{digest}",
                source_id=SOURCE_ID,
                kind=kind,
                scope=scope,
                revision=str(revision),
                digest=digest,
                collected_at=self.collected_at,
                payload=payload,
                redacted=redacted,
                truncated=truncated,
            )
        )

    def repository(self) -> None:
        capability = CAPABILITIES[0]
        try:
            response = self.http.get(API_ORIGIN + self.base)
            data = response.data
            if (
                not isinstance(data, dict)
                or not _positive_id(data.get("id"))
                or not isinstance(data.get("full_name"), str)
                or data["full_name"].lower() != self.identity["full_name"].lower()
            ):
                raise HTTPFailure("error", "repository identity mismatch or invalid response")
            branch = data.get("default_branch")
            self.default_branch = branch if isinstance(branch, str) else None
            self._record(
                "github.repository",
                self.base,
                response.body_digest,
                _select(
                    data,
                    (
                        "id",
                        "full_name",
                        "private",
                        "visibility",
                        "default_branch",
                        "archived",
                        "disabled",
                        "created_at",
                        "updated_at",
                        "pushed_at",
                    ),
                ),
            )
            self.coverage.append(
                _coverage(capability, "complete", "repository identity inspected", 1)
            )
        except HTTPFailure as error:
            self.coverage.append(_coverage(capability, error.status, error.reason))

    def workflows(self) -> None:
        """Definition references on the provider default ref; never fetch/execute YAML."""
        capability = "github.workflow_definitions"
        path = self.base + "/actions/workflows"
        count = 0
        seen: set[int] = set()
        try:
            for data, body_digest in self._pages(path, "workflows", {}):
                workflow_id = data.get("id")
                if (
                    not isinstance(workflow_id, int)
                    or not _positive_id(workflow_id)
                    or not isinstance(data.get("path"), str)
                ):
                    raise HTTPFailure("error", "invalid workflow definition reference")
                if workflow_id in seen:
                    continue
                if count >= self.max_records:
                    raise HTTPFailure("partial", "workflow definition record limit")
                seen.add(workflow_id)
                definition = _select(
                    data, ("id", "name", "path", "state", "created_at", "updated_at")
                )
                definition["default_branch"] = self.default_branch
                definition["limitations"] = [
                    "Definition reference only; symbolic default ref, YAML bytes and commit identity not collected."
                ]
                self._record("github.workflow_definition", path, body_digest, definition)
                count += 1
            self.coverage.append(
                _coverage(
                    capability,
                    "complete",
                    "visible workflow definition references inspected",
                    count,
                )
            )
        except HTTPFailure as error:
            self.coverage.append(_coverage(capability, error.status, error.reason, count))

    def _pages(
        self,
        path: str,
        key: str | None,
        params: dict[str, str],
    ) -> Iterator[tuple[dict[str, Any], str]]:
        url = API_ORIGIN + path + "?" + urlencode({**params, "per_page": "100", "page": "1"})
        seen: set[str] = set()
        received = 0
        expected_total = 0
        for page in range(self.max_pages):
            if url in seen:
                raise HTTPFailure("partial", "pagination repeated a page")
            seen.add(url)
            response = self.http.get(url)
            if key is None:
                values = response.data
            else:
                if not isinstance(response.data, dict):
                    raise HTTPFailure("error", "invalid API collection response")
                values = response.data.get(key)
                total = response.data.get("total_count")
                if not isinstance(total, int) or isinstance(total, bool) or total < 0:
                    raise HTTPFailure("error", "invalid API total count")
                expected_total = max(expected_total, total)
            if not isinstance(values, list) or any(not isinstance(value, dict) for value in values):
                raise HTTPFailure("error", "invalid API records")
            received += len(values)
            for value in values:
                yield value, response.body_digest
            next_url = response.next_url
            if next_url is None:
                if key and expected_total > received:
                    raise HTTPFailure("partial", "API result ceiling or missing pagination")
                return
            query = parse_qs(urlsplit(next_url).query, keep_blank_values=True)
            expected = {**{name: [value] for name, value in params.items()}, "per_page": ["100"]}
            if (
                set(query) != set(expected) | {"page"}
                or any(query.get(name) != value for name, value in expected.items())
                or len(query.get("page", [])) != 1
                or not query["page"][0].isdecimal()
                or int(query["page"][0]) != page + 2
            ):
                raise HTTPFailure("error", "pagination changed approved query scope")
            url = next_url
        raise HTTPFailure("partial", "API page limit")

    def actions(self, created: str, start: datetime, end: datetime) -> None:
        capability = CAPABILITIES[1]
        count = 0
        seen: set[int] = set()
        path = self.base + "/actions/runs"
        try:
            for data, body_digest in self._pages(path, "workflow_runs", {"created": created}):
                if count >= self.max_records:
                    raise HTTPFailure("partial", "Actions record limit")
                run_id = data.get("id")
                if (
                    not isinstance(run_id, int)
                    or not _positive_id(run_id)
                    or not isinstance(data.get("created_at"), str)
                ):
                    raise HTTPFailure("error", "invalid Actions run identity or timestamp")
                try:
                    stamp = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
                    in_window = stamp.tzinfo is not None and start <= stamp <= end
                except (ValueError, TypeError):
                    raise HTTPFailure("error", "invalid Actions run timestamp") from None
                if not in_window:
                    raise HTTPFailure("partial", "API returned a run outside requested time window")
                if run_id in seen:
                    continue
                seen.add(run_id)
                summary = _select(
                    data,
                    (
                        "id",
                        "name",
                        "workflow_id",
                        "run_number",
                        "run_attempt",
                        "head_branch",
                        "head_sha",
                        "event",
                        "status",
                        "conclusion",
                        "created_at",
                        "updated_at",
                        "run_started_at",
                    ),
                )
                commit = data.get("head_commit")
                if isinstance(commit, dict):
                    summary["head_commit"] = _select(commit, ("id", "tree_id", "timestamp"))
                summary["window"] = {"start": start.isoformat(), "end": end.isoformat()}
                self._record("github.actions_run", path, body_digest, summary)
                count += 1
            self.coverage.append(
                _coverage(capability, "complete", "bounded Actions run summaries inspected", count)
            )
        except HTTPFailure as error:
            self.coverage.append(_coverage(capability, error.status, error.reason, count))

    def rulesets(self) -> None:
        capability = CAPABILITIES[2]
        count = 0
        seen: set[int] = set()
        path = self.base + "/rulesets"
        status: CoverageStatus = "complete"
        reasons: list[str] = []
        detail_failures: set[CoverageStatus] = set()
        try:
            for listed, _ in self._pages(path, None, {"includes_parents": "true"}):
                rule_id = listed.get("id")
                if not isinstance(rule_id, int) or not _positive_id(rule_id):
                    raise HTTPFailure("error", "invalid ruleset identity")
                if rule_id in seen:
                    continue
                if len(seen) >= min(self.max_records, MAX_RULESET_DETAILS):
                    raise HTTPFailure("partial", "ruleset detail or record limit")
                seen.add(rule_id)
                endpoint = f"{path}/{rule_id}"
                try:
                    response = self.http.get(API_ORIGIN + endpoint)
                    data = response.data
                    if (
                        not isinstance(data, dict)
                        or data.get("id") != rule_id
                        or not isinstance(data.get("rules"), list)
                    ):
                        raise HTTPFailure("error", "invalid ruleset detail")
                    self._record(
                        "github.ruleset",
                        endpoint,
                        response.body_digest,
                        _select(
                            data,
                            (
                                "id",
                                "name",
                                "target",
                                "source_type",
                                "source",
                                "enforcement",
                                "conditions",
                                "rules",
                                "bypass_actors",
                                "created_at",
                                "updated_at",
                            ),
                        ),
                    )
                    count += 1
                except HTTPFailure as error:
                    status = "partial"
                    reasons.append(error.reason)
                    detail_failures.add(error.status)
                    if error.status == "rate_limited":
                        raise
            if count == 0 and len(detail_failures) == 1:
                status = next(iter(detail_failures))
            reason = (
                "; ".join(dict.fromkeys(reasons))
                if reasons
                else "visible rulesets inspected; not effective integration policy"
            )
            self.coverage.append(_coverage(capability, status, reason, count))
        except HTTPFailure as error:
            self.coverage.append(_coverage(capability, error.status, error.reason, count))


def _positive_id(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _select(value: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {name: value[name] for name in fields if name in value}


def _clean(value: Any, token: str | None, depth: int = 0) -> tuple[Any, bool, bool]:
    """JSON-safe normalization; bound nesting/strings/containers before reporting."""
    if depth > 12:
        return "[TRUNCATED]", False, True
    if isinstance(value, str):
        redacted = token is not None and token in value
        if token and redacted:
            value = value.replace(token, "[REDACTED]")
        cleaned, detected = sanitize(value)
        return cleaned[:4096], redacted or detected, len(cleaned) > 4096
    if value is None or isinstance(value, (bool, int, float)):
        return value, False, False
    redacted = False
    truncated = len(value) > 1000
    if isinstance(value, list):
        result_list: list[Any] = []
        for item in value[:1000]:
            clean, hidden, cut = _clean(item, token, depth + 1)
            result_list.append(clean)
            redacted |= hidden
            truncated |= cut
        return result_list, redacted, truncated
    if isinstance(value, dict):
        result_dict: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 1000:
                break
            clean_key, hidden_key, cut_key = _clean(key, token, depth + 1)
            clean, hidden, cut = _clean(item, token, depth + 1)
            if sensitive_key(key):
                clean, hidden = "[REDACTED]", True
            result_dict[str(clean_key)] = clean
            redacted |= hidden or hidden_key
            truncated |= cut or cut_key
        return result_dict, redacted, truncated
    return "[UNSUPPORTED]", False, True
