from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import git

from tackrack.application.inspection import inspect
from tackrack.domain.models import digest_bytes
from tackrack.infrastructure.state import Store
from tackrack.plugins.sources.local_git import SnapshotProbe, active_path, collect_snapshot


def write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def manifest(root: Path) -> dict[str, tuple[bytes | str, int]]:
    return {
        str(path.relative_to(root)): (
            os.readlink(path) if path.is_symlink() else path.read_bytes(),
            path.lstat().st_mode,
        )
        for path in root.rglob("*")
        if path.is_symlink() or path.is_file()
    }


def test_embedded_skill_preserves_all_revisions_and_target_bytes(repo: Path) -> None:
    relative = ".agents/skills/shipping/SKILL.md"
    path = write(repo, relative, "HEAD shipping instructions.\n")
    git(repo, "add", "-f", relative)
    git(repo, "commit", "-m", "embedded skill")
    path.write_text("Index shipping instructions.\n")
    git(repo, "add", "-f", relative)
    path.write_text("Working shipping instructions.\n")
    path.chmod(0o755)
    before = manifest(repo)
    probe = SnapshotProbe(repo)
    snapshot, result = collect_snapshot(repo, agents_mode="embedded", probe=probe)
    rows = {
        item.revision: item.excerpt
        for item in result.evidence
        if item.path == relative and item.kind == "file"
    }
    assert rows == {
        "head": "HEAD shipping instructions.\n",
        "index": "Index shipping instructions.\n",
        "working": "Working shipping instructions.\n",
    }
    assert all(item.scope == "project" for item in result.evidence)
    assert {item.revision for item in result.evidence if item.kind == "index_leak"} == {
        "head",
        "index",
    }
    assert any(item.path == relative and item.mode == "100755" for item in snapshot.entries)
    assert not probe.changed()
    assert manifest(repo) == before
    path.write_text("Changed embedded instructions.\n")
    assert probe.changed()
    changed, _ = collect_snapshot(repo, agents_mode="embedded")
    assert changed.fingerprint != snapshot.fingerprint


def test_ordinary_agents_is_product_not_fabricated_workbench(repo: Path) -> None:
    relative = ".agents/skills/SKILL.md"
    write(repo, relative, "# Shared skill\nReview changes before shipping.\n")
    before = manifest(repo)
    store = Store([repo])
    try:
        report = inspect(repo, store, command="scan", offline=True)
    finally:
        store.close()
    assert report.attachment.slot_role == "embedded"
    assert report.attachment.snapshot is None
    assert any(item.path == relative and item.scope == "project" for item in report.evidence)
    assert not any(item.scope == "workbench" for item in report.evidence)
    assert manifest(repo) == before


def test_ignored_unregistered_surfaces_are_bounded_and_witnessed(repo: Path) -> None:
    relative = ".agents/skills/unregistered/SKILL.md"
    write(repo, relative, "# Unregistered skill\nReview changes.\n")
    write(repo, ".agents/instructions/review.md", "Review instructions.\n")
    write(repo, ".agents/profiles/manual/profile.toml", "enabled = false\n")
    write(repo, ".agents/tools/review.toml", "enabled = true\n")
    excluded = [
        ".agents/unrelated/dump.txt",
        ".agents/skills/node_modules/pkg/SKILL.md",
        ".agents/skills/cache/raw.txt",
        ".agents/sessions/session.json",
        ".agents/skills/private/notes.md",
        ".agents/tools/.env.production",
    ]
    for path in excluded:
        write(repo, path, "private payload must not be read\n")
    write(repo, "ignored/arbitrary.txt", "ordinary ignored content\n")
    probe = SnapshotProbe(repo)
    snapshot, result = collect_snapshot(repo, agents_mode="embedded", probe=probe)
    paths = {item.path for item in result.evidence if item.kind == "file"}
    assert paths >= {
        relative,
        ".agents/instructions/review.md",
        ".agents/profiles/manual/profile.toml",
        ".agents/tools/review.toml",
    }
    assert not paths.intersection(excluded)
    assert "ignored/arbitrary.txt" not in paths
    assert "companion_content_excluded" in snapshot.scope["exclusion_diagnostics"]
    assert snapshot.status == "stable"
    assert all(item.status == "complete" for item in result.coverage)
    assert not probe.changed()
    write(repo, ".agents/skills/new/SKILL.md", "New skill.\n")
    assert probe.changed()


@pytest.mark.parametrize(
    "relative",
    [
        ".agents/credentials/auth.json",
        ".agents/skills/private/.env",
        ".agents/tools/.env.production",
        ".agents/profiles/manual/credentials.json",
        ".agents/auth.json",
    ],
)
def test_sensitive_tracked_payload_excluded_but_exact_leaks_visible(
    repo: Path,
    relative: str,
) -> None:
    payload = '{"password":"private-payload"}\n'
    write(repo, relative, payload)
    git(repo, "add", "-f", relative)
    git(repo, "commit", "-m", "private fixture")
    object_id = git(repo, "rev-parse", f"HEAD:{relative}").decode().strip()
    snapshot, result = collect_snapshot(repo, agents_mode="embedded")
    entries = [item for item in snapshot.entries if item.path == relative]
    assert {item.revision for item in entries} == {"head", "index"}
    assert all(item.mode == "100644" and item.stage == 0 for item in entries)
    assert all(
        item.object_id is None and item.digest == "private-sensitive-content" for item in entries
    )
    evidence = [item for item in result.evidence if item.path == relative]
    assert {item.revision for item in evidence} == {"head", "index"}
    assert all(item.kind == "index_leak" for item in evidence)
    assert all("private-payload" not in item.excerpt for item in evidence)
    assert "embedded_agents_content_excluded" in snapshot.scope["exclusion_diagnostics"]
    assert "sensitive_content_identity_withheld" in snapshot.scope["exclusion_diagnostics"]
    assert snapshot.status == "stable"
    assert all(item.status == "complete" for item in result.coverage)
    assert all(item.redacted and item.payload["content_identity_withheld"] for item in evidence)
    exported = snapshot.model_dump_json() + result.model_dump_json()
    assert object_id not in exported
    assert digest_bytes(payload.encode()) not in exported
    assert "private-payload" not in exported


@pytest.mark.parametrize("mode", ["boundary", "none"])
def test_boundary_and_none_withhold_agents_content_keep_leaks(repo: Path, mode: str) -> None:
    relative = ".agents/skills/shipping/SKILL.md"
    write(repo, relative, "Embedded instructions.\n")
    git(repo, "add", "-f", relative)
    git(repo, "commit", "-m", "fixture")
    before = manifest(repo)
    snapshot, result = collect_snapshot(repo, agents_mode=mode)
    assert not any(
        item.revision == "working" and item.path == relative for item in snapshot.entries
    )
    assert all(item.kind == "index_leak" for item in result.evidence if item.path == relative)
    assert manifest(repo) == before


def test_independent_attachment_partition_and_product_leaks(repo: Path) -> None:
    relative = ".agents/skills/shipping/SKILL.md"
    write(repo, relative, "Leaked product instructions.\n")
    git(repo, "add", "-f", relative)
    git(repo, "commit", "-m", "product leak")
    agents = repo / ".agents"
    git(agents, "init", "--template=", "--initial-branch=main")
    write(agents, "skills/shipping/SKILL.md", "Independent instructions.\n")
    git(agents, "add", "skills")
    git(agents, "commit", "-m", "independent skill")
    before = manifest(repo)
    _, product = collect_snapshot(repo, agents_mode="boundary")
    _, companion = collect_snapshot(agents, "workbench")
    assert all(item.kind == "index_leak" for item in product.evidence if item.path == relative)
    assert any(
        item.scope == "workbench"
        and item.path == "skills/shipping/SKILL.md"
        and item.excerpt == "Independent instructions.\n"
        for item in companion.evidence
    )
    assert not any(item.scope == "project" for item in companion.evidence)
    assert manifest(repo) == before


def test_nested_agents_discovery_and_unsafe_links(repo: Path, tmp_path: Path) -> None:
    relative = "ignored/nested/.agents/skills/SKILL.md"
    write(repo, relative, "Nested development skill.\n")
    secret = tmp_path / "outside"
    secret.mkdir()
    write(secret, "SKILL.md", "Outside private instructions.\n")
    (repo / "ignored/nested/.agents/skills/external").symlink_to(secret, target_is_directory=True)
    write(repo, ".agents/skills/example/SKILL.md.template", "Inert template.\n")
    write(repo, ".agents/skills/example/inert.fixture.json", "{}\n")
    snapshot, result = collect_snapshot(repo, agents_mode="embedded")
    assert any(
        item.path == relative and item.excerpt == "Nested development skill.\n"
        for item in result.evidence
    )
    assert not any("Outside private" in item.excerpt for item in result.evidence)
    assert any(item.mode == "120000" for item in snapshot.entries)
    assert active_path(relative)
    assert active_path(".agents/skills/SKILL.md")
    assert not active_path(".agents/skills/example/SKILL.md.template")
    assert not active_path(".agents/skills/example/inert.fixture.json")


def test_attachment_none_avoids_embedded_content_in_report(repo: Path) -> None:
    relative = ".agents/skills/SKILL.md"
    write(repo, relative, "Not requested embedded skill.\n")
    git(repo, "add", "-f", relative)
    git(repo, "commit", "-m", "fixture")
    before = manifest(repo)
    store = Store([repo])
    try:
        report = inspect(repo, store, command="scan", offline=True, attachment_mode="none")
    finally:
        store.close()
    assert report.attachment.snapshot is None
    assert all(item.kind == "index_leak" for item in report.evidence if item.path == relative)
    assert not any(item.scope == "workbench" for item in report.evidence)
    assert manifest(repo) == before


def test_unsafe_embedded_root_never_follows_link(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    write(outside, "skills/SKILL.md", "Private outside content.\n")
    (repo / ".agents").symlink_to(outside, target_is_directory=True)
    before = manifest(repo)
    snapshot, result = collect_snapshot(repo, agents_mode="embedded")
    assert not any("Private outside content" in item.excerpt for item in result.evidence)
    assert "embedded_agents_symlink_not_followed" in snapshot.reasons
    assert manifest(repo) == before


def test_embedded_discovery_witnesses_new_nested_ignored_surface(repo: Path) -> None:
    write(repo, "ignored/existing.txt", "Ordinary ignored file.\n")
    probe = SnapshotProbe(repo)
    collect_snapshot(repo, agents_mode="embedded", probe=probe)
    assert not probe.changed()
    write(repo, "ignored/new/.agents/skills/SKILL.md", "New ignored skill.\n")
    assert probe.changed()


def test_embedded_limits_are_reported(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tackrack.plugins.sources import local_git

    write(repo, ".agents/skills/SKILL.md", "A skill larger than the collection byte limit.\n")
    monkeypatch.setattr(local_git, "MAX_FILE", 8)
    snapshot, result = collect_snapshot(repo, agents_mode="embedded")
    assert "file_or_total_size_limit" in snapshot.reasons
    assert not any(item.path == ".agents/skills/SKILL.md" for item in result.evidence)
    assert any(item.path == ".agents/skills/SKILL.md" for item in snapshot.entries)
    assert any(item.status == "partial" for item in result.coverage)
