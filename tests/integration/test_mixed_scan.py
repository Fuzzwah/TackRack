from __future__ import annotations

import json
from pathlib import Path

from conftest import git
from typer.testing import CliRunner

from tackrack.application.inspection import inspect
from tackrack.cli import app
from tackrack.infrastructure.state import Store


def materialise_mixed_project(repo: Path) -> None:
    files = {
        "AGENTS.md": "# Guidance\nThe application uses event sourcing.\nRun scripts/check.py before completing a change.\nEvery change requires a reviewed plan.\nSee [architecture](docs/architecture.md).\n",
        ".omp/commands/opsx-propose.md": "# OpenSpec propose\nUse openspec context --json; --store <id> selects an external registered store.\nWithout a store, use openspec/specs/.\n",
        ".omp/skills/openspec-apply-change/SKILL.md": "---\nname: openspec-apply-change\n---\nUse openspec apply to implement an approved change.\n",
        ".agents/skills/shipit/SKILL.md": "---\nname: shipit\n---\nFollow [guidance](../../../AGENTS.md) and [testing](../../../docs/testing.md).\nRun scripts/check.py before shipping.\n",
        "docs/architecture.md": "Project-owned architecture.\n",
        "docs/testing.md": "Project-owned verification guidance.\n",
        "scripts/check.py": "print('shared product check')\n",
    }
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    git(repo, "add", "-f", *files)
    git(repo, "commit", "-m", "mixed fixture")


def manifest(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mode)
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def test_mixed_source_scan_is_discovery_not_a_separation_failure(repo: Path) -> None:
    materialise_mixed_project(repo)
    before = manifest(repo)
    with_store = Store([repo])
    report = inspect(repo, with_store, command="scan", offline=True)
    with_store.close()
    assert report.exit_code == 0
    assert report.policy_result == "not_assessed"
    assert report.attachment.slot_role == "embedded"
    assert report.attachment.snapshot is None
    assert all(
        e.scope == "project" for e in report.evidence if e.path == ".agents/skills/shipit/SKILL.md"
    )
    assert {
        e.revision
        for e in report.evidence
        if e.path == ".agents/skills/shipit/SKILL.md" and e.kind == "file"
    } == {"head", "index", "working"}
    assert not {"TR-A001", "TR-A017", "TR-A018", "TR-A019"} & {f.rule_id for f in report.findings}
    assert any("OMP" in tool.name or "Oh My Pi" in tool.name for tool in report.tooling)
    assert any("OpenSpec" in tool.name for tool in report.tooling)
    ship = next(
        item for item in report.extraction.items if item.path == ".agents/skills/shipit/SKILL.md"
    )
    assert ship.scope == "project"
    assert ship.disposition in {"move", "review"}
    assert (
        next(item for item in report.extraction.items if item.path == "AGENTS.md").disposition
        == "split"
    )
    assert any(
        item.path == "scripts/check.py" and item.disposition == "keep"
        for item in report.extraction.items
    )
    assert not any(
        f.rule_id == "TR-A008" and "openspec/specs" in f.explanation for f in report.findings
    )
    assert manifest(repo) == before


def test_mixed_source_audit_retains_explicit_target_boundary_failures(repo: Path) -> None:
    materialise_mixed_project(repo)
    store = Store([repo])
    report = inspect(repo, store, command="audit", offline=True)
    store.close()
    assert report.exit_code == 1
    assert report.policy_result == "fail"
    assert {"TR-A001", "TR-A017", "TR-A019"} <= {f.rule_id for f in report.findings}
    assert report.attachment.slot_role == "embedded"
    assert report.verdicts["product_git_boundary"] == "fail"


def test_cli_scan_reports_existing_tooling_without_policy_exit_failure(repo: Path) -> None:
    materialise_mixed_project(repo)
    result = CliRunner().invoke(app, ["scan", str(repo), "--offline", "--format", "json"])
    report = json.loads(result.stdout)
    assert result.exit_code == 0
    assert report["policy_result"] == "not_assessed"
    assert report["tooling"]
    assert report["extraction"]["status"] in {"review_required", "blocked"}


def test_attachment_none_keeps_embedded_index_ownership_without_payload(repo: Path) -> None:
    materialise_mixed_project(repo)
    store = Store([repo])
    report = inspect(repo, store, command="scan", offline=True, attachment_mode="none")
    store.close()
    assert any(
        e.kind == "index_leak" and e.path == ".agents/skills/shipit/SKILL.md"
        for e in report.evidence
    )
    assert not any(
        e.kind == "file" and e.path.startswith(".agents/") for e in report.evidence if e.path
    )
    assert report.policy_result == "not_assessed"
