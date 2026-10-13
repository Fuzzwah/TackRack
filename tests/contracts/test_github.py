"""Fixture-only synthetic GitHub responses; no real repository or API evidence."""

from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest

from tackrack.domain.models import canonical_digest
from tackrack.infrastructure.http import (
    API_ORIGIN,
    API_VERSION,
    MAX_BODY_BYTES,
    GitHubHTTP,
    HTTPFailure,
)
from tackrack.plugins.contracts import CollectionRequest, SourceContext, SourceProbeRequest
from tackrack.plugins.sources.github import CAPABILITIES, DEFERRED, GitHubSource, remote_identity

NOW = "2026-10-13T12:00:00+00:00"
BASE = "/repos/fixture-owner/fixture-repo"
IDENTITY = {"id": 1, "full_name": "fixture-owner/fixture-repo", "default_branch": "main"}


@pytest.fixture(autouse=True)
def no_external_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TACKRACK_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)


def request(**kwargs: Any) -> CollectionRequest:
    return replace(
        CollectionRequest(
            root=Path("/fixture-only"),
            offline=False,
            network_authorized=True,
            remote_url="git@github.com:fixture-owner/fixture-repo.git",
        ),
        **kwargs,
    )


def run_fixture(handler: Any, **kwargs: Any) -> Any:
    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        return GitHubSource().collect(
            request(**kwargs), SourceContext(clock=lambda: NOW, http=client)
        )


def statuses(result: Any) -> dict[str, str]:
    return {coverage.capability: coverage.status for coverage in result.coverage}


def run_record(run_id: int = 2, **kwargs: Any) -> dict[str, Any]:
    return {
        "id": run_id,
        "name": "fixture-only checks",
        "head_sha": "a" * 40,
        "head_branch": "main",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-10-12T00:00:00Z",
        "updated_at": "2026-10-12T00:01:00Z",
        "run_started_at": "2026-10-12T00:00:01Z",
        "head_commit": {
            "id": "a" * 40,
            "timestamp": "2026-10-11T23:59:00Z",
            "message": "do not collect code or commit message",
        },
        **kwargs,
    }


def empty_fixture(req: httpx.Request) -> httpx.Response:
    if req.url.path == BASE:
        return httpx.Response(200, json=IDENTITY)
    if req.url.path == BASE + "/actions/runs":
        return httpx.Response(200, json={"total_count": 0, "workflow_runs": []})
    if req.url.path == BASE + "/rulesets":
        return httpx.Response(200, json=[])
    if req.url.path == BASE + "/actions/workflows":
        return httpx.Response(200, json={"total_count": 0, "workflows": []})
    raise AssertionError("unexpected fixture-only endpoint")


@pytest.mark.parametrize(
    "remote",
    [
        "git@github.com:fixture-owner/fixture-repo.git",
        "ssh://git@github.com/fixture-owner/fixture-repo.git",
        "https://github.com/fixture-owner/fixture-repo",
    ],
)
def test_static_mapping_and_descriptor(remote: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("static probe must not access process or network")

    monkeypatch.setattr(httpx.Client, "send", forbidden)
    import subprocess

    monkeypatch.setattr(subprocess, "run", forbidden)
    source = GitHubSource()
    probe = source.probe(SourceProbeRequest(Path("/fixture-only"), remote))
    assert probe.eligible
    assert probe.identity["full_name"] == "fixture-owner/fixture-repo"
    assert source.describe().capabilities == list(CAPABILITIES)
    assert source.describe().permissions == ["network:https://api.github.com"]
    assert not set(DEFERRED) & set(source.describe().capabilities)


@pytest.mark.parametrize(
    "remote",
    [
        "https://user:secret@github.com/owner/repo",
        "https://token@github.com/owner/repo",
        "https://github.com.evil.test/owner/repo",
        "https://github.com:443/owner/repo",
        "http://github.com/owner/repo",
        "git://github.com/owner/repo",
        "ssh://user@github.com/owner/repo",
        "git@enterprise.test:owner/repo.git",
        "https://github.com/owner/repo?token=secret",
        "https://github.com/owner/repo#fragment",
        "https://github.com/owner/%2e%2e",
        "https://github.com/owner/../repo",
        "git@github.com:owner/..",
        "git@github.com:owner/repo\n",
        "https://github.com/ghp_abcdefghijklmnopqrstuv/repo",
    ],
)
def test_reject_unsafe_remote(remote: str) -> None:
    assert remote_identity(remote) is None


@pytest.mark.parametrize(
    "options",
    [
        {"offline": True},
        {"network_authorized": False},
        {"remote_url": "https://evil.test/a/b"},
    ],
)
def test_uninspected_never_sends(options: dict[str, Any]) -> None:
    def forbidden(req: httpx.Request) -> httpx.Response:
        raise AssertionError("uninspected collection sent a request")

    result = run_fixture(forbidden, **options)
    assert result.evidence == []
    assert all(statuses(result)[cap] == "not_inspected" for cap in CAPABILITIES)
    assert all(statuses(result)[cap] == "unsupported" for cap in DEFERRED)


def test_identity_and_zero_activity_have_independent_complete_coverage() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "GET"
        assert str(req.url).startswith(API_ORIGIN)
        assert req.headers["X-GitHub-Api-Version"] == API_VERSION
        assert "authorization" not in req.headers
        if req.url.path.endswith("/actions/runs"):
            assert "2026-09-13T12:00:00+00:00" in req.url.params["created"]
            assert req.url.params["per_page"] == "100"
        return empty_fixture(req)

    result = run_fixture(handler)
    assert len(result.evidence) == 1
    assert all(statuses(result)[cap] == "complete" for cap in CAPABILITIES)
    assert [coverage.result_count for coverage in result.coverage[:3]] == [1, 0, 0]
    evidence = result.evidence[0]
    assert evidence.digest == canonical_digest(evidence.payload)
    assert (
        evidence.payload["provenance"]["response_digest"]
        == sha256(httpx.Response(200, json=IDENTITY).content).hexdigest()
    )
    assert evidence.collected_at == NOW
    json.loads(result.model_dump_json())


@pytest.mark.parametrize(
    "code,status", [(401, "permission_denied"), (403, "permission_denied"), (404, "unavailable")]
)
def test_denial_is_not_absence_and_does_not_block_other_capabilities(
    code: int, status: str
) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/actions/runs"):
            return httpx.Response(code, json={"message": "fixture-only denial secret=do-not-echo"})
        return empty_fixture(req)

    result = run_fixture(handler)
    assert statuses(result)["github.repository"] == "complete"
    assert statuses(result)["github.actions_runs"] == status
    assert statuses(result)["github.rulesets"] == "complete"
    assert "do-not-echo" not in result.model_dump_json()


def test_paginated_runs_and_ruleset_details_preserve_commit_ref_event_timestamps() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/actions/runs"):
            page = req.url.params["page"]
            headers = {}
            if page == "1":
                query = dict(req.url.params)
                query["page"] = "2"
                headers = {
                    "Link": f'<{API_ORIGIN}{BASE}/actions/runs?{urlencode(query)}>; rel="next"'
                }
            return httpx.Response(
                200,
                headers=headers,
                json={"total_count": 2, "workflow_runs": [run_record(int(page) + 1)]},
            )
        if req.url.path == BASE + "/rulesets":
            assert req.url.params["includes_parents"] == "true"
            return httpx.Response(
                200, json=[{"id": 4, "_links": {"self": {"href": "https://evil.test/never"}}}]
            )
        if req.url.path == BASE + "/rulesets/4":
            return httpx.Response(
                200,
                json={
                    "id": 4,
                    "name": "fixture-only protection",
                    "enforcement": "active",
                    "target": "branch",
                    "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
                    "rules": [
                        {
                            "type": "required_status_checks",
                            "parameters": {"required_status_checks": [{"context": "checks"}]},
                        }
                    ],
                },
            )
        return empty_fixture(req)

    result = run_fixture(handler)
    assert len(result.evidence) == 4
    assert all(statuses(result)[cap] == "complete" for cap in CAPABILITIES)
    run = result.evidence[1]
    assert run.revision == "a" * 40
    assert run.payload["data"]["head_branch"] == "main"
    assert run.payload["data"]["event"] == "push"
    assert run.payload["data"]["head_commit"]["timestamp"] == "2026-10-11T23:59:00Z"
    assert "message" not in run.payload["data"]["head_commit"]


@pytest.mark.parametrize(
    "headers,code",
    [
        ({"x-ratelimit-remaining": "0"}, 403),
        ({"Retry-After": "9999"}, 403),
        ({}, 429),
    ],
)
def test_rate_limit_is_bounded_and_separate(headers: dict[str, str], code: int) -> None:
    calls = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal calls
        if req.url.path.endswith("/actions/runs"):
            calls += 1
            return httpx.Response(code, headers=headers, json={"message": "fixture-only limit"})
        return empty_fixture(req)

    result = run_fixture(handler)
    assert calls == 1
    assert statuses(result)["github.actions_runs"] == "rate_limited"
    assert statuses(result)["github.rulesets"] == "complete"


def test_record_and_page_limits_are_reported() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/actions/runs"):
            query = dict(req.url.params)
            query["page"] = "2"
            return httpx.Response(
                200,
                headers={
                    "Link": f'<{API_ORIGIN}{BASE}/actions/runs?{urlencode(query)}>; rel="next"'
                },
                json={"total_count": 2, "workflow_runs": [run_record(int(req.url.params["page"]))]},
            )
        return empty_fixture(req)

    result = run_fixture(handler, max_pages=1)
    assert statuses(result)["github.actions_runs"] == "partial"
    assert len(result.evidence) == 2
    limited = run_fixture(handler, max_records=1)
    assert len(limited.evidence) == 2
    assert statuses(limited)["github.actions_runs"] == "partial"
    assert statuses(limited)["github.rulesets"] == "complete"


@pytest.mark.parametrize(
    "target",
    [
        "http://api.github.com/repos/fixture-owner/fixture-repo/actions/runs?page=2",
        "https://api.github.com.evil.test/repos/fixture-owner/fixture-repo/actions/runs?page=2",
        "https://secret@api.github.com/repos/fixture-owner/fixture-repo/actions/runs?page=2",
        "https://api.github.com:444/repos/fixture-owner/fixture-repo/actions/runs?page=2",
        "https://api.github.com/repos/other/repo/actions/runs?page=2",
        "https://api.github.com/repos/fixture-owner/fixture-repo/contents/secret",
        "https://api.github.com/repos/fixture-owner/fixture-repo/actions/runs?token=secret&page=2",
    ],
)
def test_pagination_origin_or_scope_attacks_never_follow(target: str) -> None:
    visited: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        visited.append(str(req.url))
        if req.url.path.endswith("/actions/runs"):
            return httpx.Response(
                200,
                headers={"Link": f'<{target}>; rel="next"'},
                json={"total_count": 1, "workflow_runs": [run_record()]},
            )
        return empty_fixture(req)

    result = run_fixture(handler)
    assert statuses(result)["github.actions_runs"] == "error"
    assert target not in visited
    assert "secret" not in result.model_dump_json()


def test_redirects_refused_even_when_injected_client_follows_them() -> None:
    visited: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        visited.append(str(req.url))
        if req.url.path == BASE:
            return httpx.Response(302, headers={"Location": "https://evil.test/steal"})
        return empty_fixture(req)

    result = run_fixture(handler)
    assert statuses(result)["github.repository"] == "error"
    assert "https://evil.test/steal" not in visited


def test_explicit_token_only_is_secret_safe_and_not_in_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "fixture-only-custom-secret-token"
    monkeypatch.setenv("TACKRACK_GITHUB_TOKEN", token)
    monkeypatch.setenv("GITHUB_TOKEN", "ambient-secret-must-not-be-used")

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["Authorization"] == f"Bearer {token}"
        assert token not in str(req.url)
        if req.url.path.endswith("/actions/runs"):
            return httpx.Response(
                200,
                json={
                    "total_count": 1,
                    "workflow_runs": [run_record(name=token, logs_url="https://evil.test/never")],
                },
            )
        return empty_fixture(req)

    result = run_fixture(handler)
    assert token not in result.model_dump_json()
    assert "ambient-secret" not in result.model_dump_json()
    assert result.evidence[1].redacted
    assert result.evidence[1].payload["data"]["name"] == "[REDACTED]"
    assert all(record.digest == canonical_digest(record.payload) for record in result.evidence)


def test_ambient_tokens_and_injected_client_auth_are_not_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ambient-secret")
    monkeypatch.setenv("GH_TOKEN", "other-ambient-secret")

    def handler(req: httpx.Request) -> httpx.Response:
        assert "authorization" not in req.headers
        assert "cookie" not in req.headers
        return empty_fixture(req)

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        auth=("user", "password"),
        cookies={"secret": "value"},
    ) as client:
        result = GitHubSource().collect(request(), SourceContext(clock=lambda: NOW, http=client))
    assert statuses(result)["github.repository"] == "complete"


def test_body_limits_and_invalid_json_have_bounded_sanitized_errors() -> None:
    for response in (
        httpx.Response(200, content=b"x" * (MAX_BODY_BYTES + 1)),
        httpx.Response(200, content=b'{"secret": NaN}'),
        httpx.Response(200, content=b"password=fixture-secret-not-json"),
    ):

        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == BASE:
                return response
            return empty_fixture(req)

        result = run_fixture(handler)
        assert statuses(result)["github.repository"] in {"partial", "error"}
        assert "fixture-secret" not in result.model_dump_json()
        assert statuses(result)["github.actions_runs"] == "complete"


@pytest.mark.parametrize("failure", ["transport", "server"])
def test_transient_retries_never_exceed_three(failure: str) -> None:
    attempts = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal attempts
        if req.url.path == BASE:
            attempts += 1
            if failure == "transport":
                raise httpx.ConnectError("fixture secret=must-not-echo", request=req)
            return httpx.Response(503, json={"message": "fixture secret=must-not-echo"})
        return empty_fixture(req)

    result = run_fixture(handler)
    assert attempts == 3
    assert statuses(result)["github.repository"] == "error"
    assert "must-not-echo" not in result.model_dump_json()


def test_invalid_token_never_sends_or_echoes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TACKRACK_GITHUB_TOKEN", "fixture-secret\ninvalid")

    def forbidden(req: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid header token should never be sent")

    result = run_fixture(forbidden)
    assert all(statuses(result)[cap] == "error" for cap in CAPABILITIES)
    assert "fixture-secret" not in result.model_dump_json()


def test_time_window_and_record_truncation_are_explicit() -> None:
    def outside(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/actions/runs"):
            return httpx.Response(
                200,
                json={
                    "total_count": 1,
                    "workflow_runs": [run_record(created_at="2020-01-01T00:00:00Z")],
                },
            )
        return empty_fixture(req)

    assert statuses(run_fixture(outside))["github.actions_runs"] == "partial"

    def long_name(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/actions/runs"):
            return httpx.Response(
                200, json={"total_count": 1, "workflow_runs": [run_record(name="x" * 5000)]}
            )
        return empty_fixture(req)

    result = run_fixture(long_name, window_days=9999)
    assert result.evidence[1].truncated
    assert len(result.evidence[1].payload["data"]["name"]) == 4096


@pytest.mark.parametrize(
    "url",
    [
        "https://api.github.com@evil.test/repos/a/b",
        "https://api.github.com./repos/a/b",
        "https://api.github.com/repos/a/%2e%2e/b",
        "https://api.github.com/repos/a/../b",
        "https://api.github.com/repos/a/b#secret",
        "https://api.github.com\\evil.test/repos/a/b",
    ],
)
def test_transport_rejects_unapproved_urls_before_request(url: str) -> None:
    def forbidden(req: httpx.Request) -> httpx.Response:
        raise AssertionError("origin guard must run before sending")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        transport = GitHubHTTP(client, "fixture-token")
        with pytest.raises(HTTPFailure, match="unapproved API URL"):
            transport.get(url)


@pytest.mark.parametrize("mixed", [False, True])
def test_ruleset_detail_denial_retains_visible_evidence_without_claiming_policy(
    mixed: bool,
) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == BASE + "/rulesets":
            return httpx.Response(200, json=[{"id": 4}, {"id": 5}] if mixed else [{"id": 4}])
        if req.url.path == BASE + "/rulesets/4":
            return httpx.Response(403, json={"message": "fixture-only detail denial"})
        if req.url.path == BASE + "/rulesets/5":
            return httpx.Response(200, json={"id": 5, "rules": [{"type": "required_signatures"}]})
        return empty_fixture(req)

    result = run_fixture(handler)
    assert statuses(result)["github.rulesets"] == ("partial" if mixed else "permission_denied")
    assert statuses(result)["github.integration_policy"] == "unsupported"
    assert len(result.evidence) == (2 if mixed else 1)


def test_api_result_ceiling_is_partial_not_complete() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/actions/runs"):
            return httpx.Response(200, json={"total_count": 1001, "workflow_runs": [run_record()]})
        return empty_fixture(req)

    result = run_fixture(handler)
    assert statuses(result)["github.actions_runs"] == "partial"
    assert len(result.evidence) == 2


def test_retry_can_recover_without_duplicate_evidence() -> None:
    attempts = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal attempts
        if req.url.path == BASE:
            attempts += 1
            if attempts < 3:
                return httpx.Response(502)
        return empty_fixture(req)

    result = run_fixture(handler)
    assert attempts == 3
    assert statuses(result)["github.repository"] == "complete"
    assert len(result.evidence) == 1


def test_definition_references_are_collected_without_fetching_yaml() -> None:
    definition = {
        "id": 15,
        "name": "AI review",
        "path": ".github/workflows/review.yml",
        "state": "active",
        "updated_at": "2026-10-12T00:00:00Z",
    }

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == BASE + "/actions/workflows":
            return httpx.Response(200, json={"total_count": 1, "workflows": [definition]})
        return empty_fixture(req)  # Any source/YAML endpoint is rejected by this fixture.

    result = run_fixture(handler)
    assert statuses(result)["github.workflow_definitions"] == "complete"
    record = next(e for e in result.evidence if e.kind == "github.workflow_definition")
    assert record.payload["data"]["path"] == definition["path"]
    assert record.payload["observation"]["ref"] == "main"
    assert record.payload["observation"]["subject_commit"] is None


def test_operation_deadline_stops_all_capabilities_without_requests(monkeypatch) -> None:
    import tackrack.infrastructure.http as transport

    times = iter([0.0, 121.0, 122.0, 123.0, 124.0])
    monkeypatch.setattr(transport, "monotonic", lambda: next(times))

    def forbidden(req: httpx.Request) -> httpx.Response:
        raise AssertionError("Operation deadline must prevent network access")

    result = run_fixture(forbidden)
    assert all(statuses(result)[cap] == "partial" for cap in CAPABILITIES)


def test_low_entropy_credentials_and_raw_response_hashes_are_withheld() -> None:
    body = {**IDENTITY, "password": "1234"}
    raw = httpx.Response(200, json=body).content

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=raw) if req.url.path == BASE else empty_fixture(req)

    result = run_fixture(handler)
    exported = result.model_dump_json()
    assert "1234" not in exported
    assert sha256(raw).hexdigest() not in exported
    assert result.evidence[0].redacted


def test_duplicate_api_keys_are_error_coverage_not_overridden_metadata() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == BASE:
            return httpx.Response(
                200, content=b'{"id":1,"full_name":"fixture-owner/fixture-repo","id":2}'
            )
        return empty_fixture(req)

    assert statuses(run_fixture(handler))["github.repository"] == "error"
