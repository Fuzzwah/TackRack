from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

from conftest import git
from typer.testing import CliRunner

from tackrack.application.inspection import inspect, register
from tackrack.cli import app
from tackrack.infrastructure.state import Store
from tackrack.plugins.sources.local_git import collect_snapshot


def tree_manifest(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode)
        for p in root.rglob("*")
        if p.is_file() and not p.is_symlink()
    }


def companion(path: Path) -> Path:
    path.mkdir()
    git(path, "init", "--template=", "--initial-branch=main")
    (path / "project.toml").write_text(f'''schema_version = 1
project_id = "{uuid4()}"
companion_id = "{uuid4()}"
name = "fixture"
default_profile = "manual"
workflow_policy = "policy.toml"
shipping_contract = "shipping.toml"
''')
    profile = path / "profiles/manual"
    profile.mkdir(parents=True)
    (profile / "profile.toml").write_text("""schema_version = 1
adapter = "manual"
enabled = true
render_strategy = "manual"
context_file = "context.md"
""")
    (profile / "context.md").write_text("Explicit manual context; no automatic loading.")
    (path / "policy.toml").write_text("schema_version = 1\n")
    (path / "shipping.toml").write_text("schema_version = 1\n")
    return path


def test_clean_project_offline_and_immutable(repo: Path) -> None:
    (repo / "app.py").write_text("print('ordinary product')\n")
    git(repo, "add", ".gitignore", "app.py")
    git(repo, "commit", "-m", "fixture")
    before = tree_manifest(repo)
    store = Store([repo])
    report = inspect(repo, store, command="audit", offline=True)
    store.close()
    assert tree_manifest(repo) == before
    assert report.policy_result == "pass"
    assert report.verdicts["attachment_trust"] == "not_present"
    assert report.verdicts["product_independence"] == "not_verified"
    assert not report.components
    assert all(
        c.status == "not_inspected" for c in report.coverage if c.source_id in {"ambient", "github"}
    )


def test_dirty_revisions_preserved_and_not_staged(repo: Path) -> None:
    file = repo / "AGENTS.md"
    file.write_text("Committed architecture: event sourcing.\n")
    git(repo, "add", "-f", "AGENTS.md")
    git(repo, "commit", "-m", "fixture")
    file.write_text("Staged: every substantial change requires a reviewed plan.\n")
    git(repo, "add", "-f", "AGENTS.md")
    file.write_text("Working: run scripts/check.py before completing a change.\n")
    before = tree_manifest(repo)
    snapshot, result = collect_snapshot(repo)
    rows = {e.revision: e.excerpt for e in result.evidence if e.path == "AGENTS.md"}
    assert rows == {
        "head": "Committed architecture: event sourcing.\n",
        "index": "Staged: every substantial change requires a reviewed plan.\n",
        "working": "Working: run scripts/check.py before completing a change.\n",
    }
    assert snapshot.head is not None
    assert tree_manifest(repo) == before


def test_mixed_ignored_instruction_and_shared_resource(repo: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/mixed-instructions.fixture.json"
    data = json.loads(fixture.read_text())
    for path, text in data["files"].items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    store = Store([repo])
    report = inspect(repo, store, command="audit", offline=True)
    store.close()
    assert {f.rule_id for f in report.findings} >= {"TR-A003", "TR-A019"}
    mixed = next(c for c in report.components if c.ownership == "mixed")
    span = next(s for s in mixed.ownership_spans if s["ownership"] == "project_knowledge")
    assert (repo / "AGENTS.md").read_bytes()[
        span["byte_start"] : span["byte_end"]
    ] == b"The application uses event sourcing."
    assert all(not r.unresolved for r in report.relationships)
    assert report.verdicts["local_containment"] == "fail"
    assert (repo / "scripts/check.py").read_text() == "print('product check')\n"


def test_unregistered_ignored_companion_is_separate_and_untrusted(repo: Path) -> None:
    wb = companion(repo / ".agents")
    before = tree_manifest(repo)
    store = Store([repo, wb])
    report = inspect(repo, store, command="audit", offline=True)
    store.close()
    assert report.attachment.independent is True
    assert report.attachment.trust == "untrusted"
    assert report.attachment.snapshot is not None
    assert report.attachment.snapshot.git_common_dir != report.project.git_common_dir
    assert report.verdicts["profile_configuration"] == "not_assessed"
    assert all(not e.path.startswith(".agents/") for e in report.project.entries)
    assert any(e.scope == "workbench" and e.path == "project.toml" for e in report.evidence)
    assert tree_manifest(repo) == before


def test_none_preserves_index_leak_evidence(repo: Path) -> None:
    (repo / ".agents").mkdir()
    (repo / ".agents/leak.txt").write_text("Product accidentally owns attachment")
    git(repo, "add", "-f", ".agents/leak.txt")
    store = Store([repo])
    report = inspect(repo, store, command="audit", offline=True, attachment_mode="none")
    store.close()
    assert any(e.kind == "index_leak" and e.path == ".agents/leak.txt" for e in report.evidence)
    assert report.attachment.snapshot is None
    assert report.verdicts["product_git_boundary"] == "fail"


def test_external_registered_companion_and_fingerprint_partition(
    repo: Path, tmp_path: Path
) -> None:
    wb = companion(tmp_path / "external-ai")
    store = Store([repo, wb])
    register("sample", repo, wb, store, trust_policy=True)
    report = inspect(repo, store, command="audit", offline=True)
    assert report.attachment.layout == "external"
    assert report.verdicts["profile_configuration"] == "pass"
    (wb / "profiles/manual/context.md").write_text("Changed authored context")
    second = inspect(repo, store, command="audit", offline=True)
    store.close()
    assert report.project.fingerprint == second.project.fingerprint
    assert report.attachment.snapshot.fingerprint != second.attachment.snapshot.fingerprint


def test_stale_trusted_manifest_cannot_relax_policy(repo: Path) -> None:
    wb = companion(repo / ".agents")
    store = Store([repo, wb])
    register("sample", repo, wb, store, trust_policy=True)
    manifest = wb / "project.toml"
    manifest.write_text(manifest.read_text().replace('name = "fixture"', 'name = "changed"'))
    report = inspect(repo, store, command="audit", offline=True)
    store.close()
    assert report.verdicts["profile_configuration"] == "fail"
    assert any(f.rule_id == "TR-A008" for f in report.findings)


def test_symlink_attachment_not_followed(repo: Path, tmp_path: Path) -> None:
    target = companion(tmp_path / "unapproved")
    (repo / ".agents").symlink_to(target, target_is_directory=True)
    store = Store([repo])
    report = inspect(repo, store, command="audit", offline=True)
    store.close()
    assert report.attachment.kind == "symlink"
    assert report.attachment.snapshot is None
    assert all(e.path != "project.toml" for e in report.evidence)


def test_hostile_git_surfaces_never_execute_or_write(repo: Path) -> None:
    marker = repo.parent / "executed"
    config = repo / ".git/config"
    config.write_text(
        config.read_text()
        + f"""
[core]
    fsmonitor = touch {marker}
    hooksPath = {repo / ".git/hooks"}
[diff "evil"]
    command = touch {marker}
    textconv = touch {marker}
[remote "origin"]
    url = ext::touch {marker}
[pager]
    log = touch {marker}
"""
    )
    (repo / ".gitattributes").write_text("* diff=evil filter=evil\n")
    before = tree_manifest(repo)
    collect_snapshot(repo)
    assert not marker.exists()
    assert tree_manifest(repo) == before


def test_git_config_include_fails_closed_before_git_exec(repo: Path) -> None:
    include = repo.parent / "never-read-config"
    (repo / ".git/config").write_text(
        (repo / ".git/config").read_text() + f"\n[include]\n path = {include}\n"
    )
    snapshot, result = collect_snapshot(repo)
    assert "git_config_includes_unsupported" in snapshot.reasons
    assert all(c.status == "partial" for c in result.coverage)


def test_missing_promisor_object_never_fetches(repo: Path) -> None:
    oid = "1" * 40
    git(repo, "update-index", "--add", "--cacheinfo", f"100644,{oid},missing.txt")
    (repo / ".git/config").write_text(
        (repo / ".git/config").read_text()
        + '\n[remote "missing"]\n promisor = true\n url = https://127.0.0.1:1/forbidden\n[extensions]\n partialclone = missing\n'
    )
    before = tree_manifest(repo)
    snapshot, _ = collect_snapshot(repo)
    assert "missing_or_large_git_object" in snapshot.reasons
    assert tree_manifest(repo) == before


def test_unusual_path_bytes_and_terminal_safety(repo: Path) -> None:
    raw = os.fsencode(repo) + b"/strange-\xff-\x1b-name\n.txt"
    fd = os.open(raw, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, b"ordinary content")
    os.close(fd)
    _, result = collect_snapshot(repo)
    evidence = next(e for e in result.evidence if e.kind == "file")
    assert evidence.path_bytes
    assert "\x1b" not in evidence.path
    assert "\n" not in evidence.path


def test_runtime_ai_and_inert_detector_literals_not_live(repo: Path) -> None:
    data = json.loads(
        (Path(__file__).parents[1] / "fixtures/runtime-ai-product.fixture.json").read_text()
    )
    for name, text in data["files"].items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    store = Store([repo])
    report = inspect(repo, store, command="audit", offline=True)
    store.close()
    assert not report.findings
    assert not report.components


def test_cli_json_output_and_strict_external_destination(repo: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["audit", str(repo), "--offline", "--format", "json"])
    report = json.loads(result.stdout)
    assert result.exit_code == 0
    assert report["policy_result"] == "pass"
    rejected = runner.invoke(
        app,
        ["scan", str(repo), "--offline", "--format", "json", "--out", str(repo / "report.json")],
    )
    assert rejected.exit_code == 2
    assert (
        json.loads(rejected.stdout)["errors"][0]["reason"]
        == "output_or_state_inside_inspected_root"
    )
    assert not (repo / "report.json").exists()


def test_state_override_inside_repo_is_rejected(repo: Path, monkeypatch) -> None:
    monkeypatch.setenv("TACKRACK_STATE_DIR", str(repo / "forbidden-state"))
    result = CliRunner().invoke(app, ["audit", str(repo), "--offline", "--format", "json"])
    assert result.exit_code == 2
    assert not (repo / "forbidden-state").exists()


def test_sensitive_instruction_does_not_hide_containment_or_export_secret_identity(
    repo: Path,
) -> None:
    from tackrack.domain.models import digest_bytes

    data = b'api_key = "private-example-credential-123"\n'
    (repo / "AGENTS.md").write_bytes(data)
    store = Store([repo])
    report = inspect(repo, store, command="audit", offline=True)
    store.close()
    exported = report.model_dump_json()
    assert "private-example-credential-123" not in exported
    assert digest_bytes(data) not in exported
    assert {f.rule_id for f in report.findings} >= {"TR-A010", "TR-A019"}
    assert report.verdicts["local_containment"] == "fail"


def test_added_untracked_input_marks_snapshot_unstable(repo: Path, monkeypatch) -> None:
    from tackrack.infrastructure.git import GitBroker

    original = GitBroker.run
    calls = 0

    def changed_run(self, *args, **kwargs):
        nonlocal calls
        if args == ("ls-files", "--others", "--exclude-standard", "-z"):
            calls += 1
            if calls == 2:
                (repo / "new.txt").write_text("Concurrent product edit")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(GitBroker, "run", changed_run)
    snapshot, result = collect_snapshot(repo)
    assert snapshot.status == "changed_during_scan"
    assert all(c.status == "partial" for c in result.coverage)


def test_auto_companion_scope_omits_private_unknown_and_runtime_files(repo: Path) -> None:
    wb = companion(repo / ".agents")
    (wb / "private-notes.txt").write_text("Private unrelated data")
    (wb / "sessions.json").write_text('{"conversation": "not requested"}')
    (wb / "profiles/manual/auth.json").write_text('{"token": "private-credential-123"}')
    runtime = wb / ".local"
    runtime.mkdir()
    (runtime / "state.json").write_text('{"approval": "never authoritative here"}')
    store = Store([repo, wb])
    report = inspect(repo, store, command="audit", offline=True)
    full = inspect(repo, store, command="audit", offline=True, attachment_mode="full")
    store.close()
    observed = {e.path for e in report.evidence if e.scope == "workbench"}
    expanded = {e.path for e in full.evidence if e.scope == "workbench"}
    assert "private-notes.txt" not in observed
    assert "private-notes.txt" in expanded
    assert not {"sessions.json", "profiles/manual/auth.json", ".local/state.json"} & expanded


def test_registered_companion_subject_resolves_exact_product_binding(repo: Path) -> None:
    wb = companion(repo / ".agents")
    store = Store([repo, wb])
    register("sample", repo, wb, store, trust_policy=True)
    store.close()
    result = CliRunner().invoke(app, ["audit", str(wb), "--offline", "--format", "json"])
    report = json.loads(result.stdout)
    assert result.exit_code == 0
    assert report["project"]["root"] == str(repo)
    assert report["attachment"]["snapshot"]["root"] == str(wb)


def test_duplicate_checkout_binding_cannot_select_another_companion(
    repo: Path, tmp_path: Path
) -> None:
    import pytest

    from tackrack.infrastructure.state import StateError

    nested = companion(repo / ".agents")
    other = companion(tmp_path / "other-ai")
    store = Store([repo, nested, other])
    original = register("first", repo, nested, store)
    with pytest.raises(StateError, match="physical_checkout_already_registered"):
        register("another", repo, other, store)
    assert store.by_project(repo) == original
    store.close()


def test_registered_name_works_from_non_git_parent_with_external_state(
    repo: Path, monkeypatch
) -> None:
    wb = companion(repo / ".agents")
    store = Store([repo, wb])
    register("sample", repo, wb, store)
    store.close()
    monkeypatch.chdir(repo.parent)
    result = CliRunner().invoke(app, ["audit", "sample", "--offline", "--format", "json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["project"]["root"] == str(repo)


def test_edit_during_host_collection_invalidates_fresh_report(repo: Path, monkeypatch) -> None:
    import httpx

    import tackrack.infrastructure.http as transport

    product = repo / "app.py"
    product.write_text("before = 1\n")
    git(repo, "remote", "add", "origin", "https://github.com/fixture/example.git")
    client_type = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/fixture/example":
            product.write_text("after_ = 2\n")
            return httpx.Response(
                200, json={"id": 1, "full_name": "fixture/example", "default_branch": "main"}
            )
        if path.endswith("/actions/runs"):
            return httpx.Response(200, json={"total_count": 0, "workflow_runs": []})
        if path.endswith("/actions/workflows"):
            return httpx.Response(200, json={"total_count": 0, "workflows": []})
        if path.endswith("/rulesets"):
            return httpx.Response(200, json=[])
        raise AssertionError("Unapproved endpoint")

    monkeypatch.setattr(
        transport.httpx,
        "Client",
        lambda **kwargs: client_type(transport=httpx.MockTransport(handler)),
    )
    result = CliRunner().invoke(app, ["audit", str(repo), "--allow-network", "--format", "json"])
    assert result.exit_code == 4
    assert json.loads(result.stdout)["snapshot_status"] == "unstable"


def test_unsafe_git_failure_does_not_expand_ordinary_ignored_scope(repo: Path) -> None:
    ignored = repo / "ignored"
    ignored.mkdir()
    (ignored / "private.json").write_text('{"not_requested": "private bytes"}')
    config = repo / ".git/config"
    config.write_text(config.read_text() + "\n[include]\n path = /unapproved/config\n")
    snapshot, result = collect_snapshot(repo)
    assert "git_config_includes_unsupported" in snapshot.reasons
    assert all(e.path != "ignored/private.json" for e in result.evidence)


def test_read_only_git_broker_denies_mutating_and_execution_options(repo: Path) -> None:
    import pytest

    from tackrack.infrastructure.git import GitBroker, GitError

    broker = GitBroker(repo)
    before = tree_manifest(repo)
    for args in (
        ("config", "--local", "--null", "core.fsmonitor", "evil"),
        ("cat-file", "--textconv", "HEAD:app.py"),
        ("ls-files", "--recurse-submodules", "-z"),
    ):
        with pytest.raises(GitError, match="git_command_not_allowed"):
            broker.run(*args)
    assert tree_manifest(repo) == before


def test_tracked_hosted_development_agent_is_not_ordinary_ci(repo: Path) -> None:
    workflow = repo / ".github/workflows/review.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("jobs:\n  review:\n    steps:\n      - uses: openai/codex-action@v1\n")
    git(repo, "add", ".github/workflows/review.yml")
    store = Store([repo])
    report = inspect(repo, store, command="audit", offline=True)
    store.close()
    assert report.policy_result == "fail"
    assert report.verdicts["product_git_boundary"] == "fail"
    assert any(c.kind == "hosted_bridge" for c in report.components)
    assert any(f.rule_id == "TR-A001" for f in report.findings)


def test_workflow_examples_in_run_blocks_are_not_agent_callers(repo: Path) -> None:
    workflow = repo / ".github/workflows/checks.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "jobs:\n  tests:\n    steps:\n      - run: |\n          echo 'uses: openai/codex-action@v1'\n"
    )
    store = Store([repo])
    report = inspect(repo, store, command="audit", offline=True)
    store.close()
    assert report.policy_result == "pass"
    assert all(c.kind != "hosted_bridge" for c in report.components)


def test_ambiguous_duplicate_workflow_keys_are_inconclusive(repo: Path) -> None:
    workflow = repo / ".github/workflows/review.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("jobs:\n  review:\n    steps: []\njobs: {}\n")
    store = Store([repo])
    report = inspect(repo, store, command="audit", offline=True)
    store.close()
    assert report.policy_result == "inconclusive"
    assert report.exit_code == 3
    assert any(f.rule_id == "TR-A009" for f in report.findings)


def test_unsupported_ledger_is_not_rewritten_or_chmodded(repo: Path, tmp_path: Path) -> None:
    import sqlite3

    import pytest

    from tackrack.infrastructure.state import StateError

    state = tmp_path / "state"
    state.mkdir()
    database = state / "ledger.sqlite3"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE schema_version(version INTEGER)")
        db.execute("INSERT INTO schema_version VALUES (2)")
    database.chmod(0o644)
    before = database.read_bytes(), database.stat().st_mode
    with pytest.raises(StateError, match="unsupported_ledger_schema"):
        Store([repo])
    assert (database.read_bytes(), database.stat().st_mode) == before
