"""Exercise the standalone guard using only isolated repositories and archives."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

GUARD = Path(__file__).resolve().parents[2] / "scripts" / "check_boundary.py"
PROJECT = """[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
[project]
name = "tackrack"
version = "0.1.0"
[tool.hatch.build.targets.wheel]
packages = ["src/tackrack"]
[tool.hatch.build.targets.sdist]
include = ["/src/tackrack", "/tests", "/scripts", "/pyproject.toml"]
exclude = ["/.agents", "/.git", "/.venv"]
"""


def git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("git", path=os.defpath)
    assert executable is not None
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "HOME": str(root.parent / "empty-home"),
            "XDG_CONFIG_HOME": str(root.parent / "empty-xdg"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return subprocess.run(
        [
            executable,
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-C",
            str(root),
            *arguments,
        ],
        env=environment,
        text=True,
        capture_output=True,
        check=True,
    )


def guard(
    root: Path, *arguments: str, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        {"HOME": str(root.parent / "empty-home"), "XDG_CONFIG_HOME": str(root.parent / "empty-xdg")}
    )
    if environment:
        env.update(environment)
    return subprocess.run(
        [sys.executable, str(GUARD), "--root", str(root), *arguments],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "product"
    root.mkdir()
    git(root, "init", "--quiet")
    (root / ".gitignore").write_text("/.agents/\n/.agents\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(PROJECT, encoding="utf-8")
    return root


def test_absent_attachment_and_unborn_head_are_valid(repo: Path) -> None:
    result = guard(repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "optional attachment absent" in result.stdout
    assert "no HEAD yet" in result.stdout


def test_standalone_program_has_no_product_or_companion_import(tmp_path: Path) -> None:
    standalone = tmp_path / "check_boundary.py"
    shutil.copyfile(GUARD, standalone)
    artifact = tmp_path / "product.whl"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("tackrack/__init__.py", "")
    result = subprocess.run(
        [sys.executable, "-I", str(standalone), "--artifact-mode", "--artifact", str(artifact)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "not a Git boundary pass" in result.stdout


@pytest.mark.parametrize("kind", ["file", "symlink", "gitlink", "descendant"])
def test_exact_index_and_head_attachment_leaks(repo: Path, kind: str) -> None:
    blob = git(repo, "hash-object", "-w", "pyproject.toml").stdout.strip()
    if kind == "gitlink":
        git(repo, "add", "pyproject.toml")
        git(repo, "commit", "-m", "initial", "--quiet")
        object_id = git(repo, "rev-parse", "HEAD").stdout.strip()
        mode = "160000"
    else:
        object_id = blob
        mode = "120000" if kind == "symlink" else "100644"
    name = ".agents/owned.txt" if kind == "descendant" else ".agents"
    git(repo, "update-index", "--add", "--cacheinfo", f"{mode},{object_id},{name}")
    result = guard(repo)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL index: reserved attachment tracked" in result.stdout
    assert name in result.stdout
    assert f"mode {mode}" in result.stdout
    assert "FAIL committed:" not in result.stdout
    git(repo, "commit", "--quiet", "-m", "reserved index fixture")
    git(repo, "update-index", "--force-remove", name)
    committed = guard(repo)
    assert committed.returncode == 1, committed.stdout + committed.stderr
    assert "FAIL committed: reserved attachment tracked" in committed.stdout
    assert "FAIL index:" not in committed.stdout


def test_committed_leak_is_reported_after_index_removal(repo: Path) -> None:
    attachment = repo / ".agents"
    attachment.mkdir()
    (attachment / "private.txt").write_text("fixture", encoding="utf-8")
    git(repo, "add", "-f", ".agents/private.txt")
    git(repo, "commit", "--quiet", "-m", "leaked fixture")
    git(repo, "update-index", "--force-remove", ".agents/private.txt")
    result = guard(repo)
    assert "FAIL committed: reserved attachment tracked" in result.stdout
    assert "FAIL index:" not in result.stdout


@pytest.mark.parametrize(
    "path",
    [
        "AGENTS.md",
        "src/CLAUDE.md",
        "tests/.mcp.json",
        "ignored/.cursor/config.json",
        ".github/copilot-instructions.md",
        ".github/instructions/python.instructions.md",
    ],
)
def test_live_discovery_is_reported_even_ignored(repo: Path, path: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{}", encoding="utf-8")
    with (repo / ".gitignore").open("a", encoding="utf-8") as handle:
        handle.write(f"/{path}\n/ignored/\n")
    result = guard(repo)
    assert result.returncode == 1
    assert "live agent discovery path outside attachment" in result.stdout


def test_nested_agents_is_not_the_reserved_partition(repo: Path) -> None:
    target = repo / "src" / ".agents" / "AGENTS.md"
    target.parent.mkdir(parents=True)
    target.write_text("fixture", encoding="utf-8")
    assert "src/.agents/AGENTS.md" in guard(repo).stdout


def test_literals_docs_and_inert_fixture_are_not_dependencies(repo: Path) -> None:
    (repo / "README.md").write_text("AGENTS.md and .agents/run.py are examples", encoding="utf-8")
    (repo / "detector.py").write_text('NAMES = ["AGENTS.md", ".agents/run.py"]\n', encoding="utf-8")
    fixtures = repo / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "harness.fixture.json").write_text('{"path": ".agents"}', encoding="utf-8")
    (fixtures / "import.fixture.py").write_text("import agents\n", encoding="utf-8")
    result = guard(repo)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "path,text",
    [
        ("src/dependency.py", "import agents\n"),
        ("tests/dependency.py", 'import sys\nsys.path.insert(0, ".agents/library")\n'),
        ("scripts/build.sh", "python .agents/build.py\n"),
        (
            ".github/workflows/build.yml",
            "jobs:\n  build:\n    steps:\n      - run: python .agents/build.py\n",
        ),
    ],
)
def test_active_companion_dependencies(repo: Path, path: str, text: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    result = guard(repo)
    assert result.returncode == 1
    assert "active companion dependency" in result.stdout


@pytest.mark.parametrize(
    "text",
    [
        'from subprocess import run as execute\nexecute(["python", ".agents/build.py"])\n',
        'import sys as runtime\nruntime.path = [".agents/library"]\n',
        'import sys\nCOMPANION = ".agents/library"\nsys.path.append(COMPANION)\n',
    ],
)
def test_aliased_and_bound_import_execution_dependencies(repo: Path, text: str) -> None:
    (repo / "dependency.py").write_text(text, encoding="utf-8")
    assert "active companion dependency" in guard(repo).stdout


def test_ci_environment_dependency(repo: Path) -> None:
    workflow = repo / ".github" / "workflows" / "check.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("env:\n  PYTHONPATH: .agents/library\njobs: {}\n", encoding="utf-8")
    assert "active companion dependency" in guard(repo).stdout


def test_test_configuration_companion_dependency(repo: Path) -> None:
    with (repo / "pyproject.toml").open("a", encoding="utf-8") as handle:
        handle.write('[tool.pytest.ini_options]\npythonpath = [".agents/lib"]\n')
    assert "active companion dependency in pyproject.toml" in guard(repo).stdout


def test_attachment_requires_effective_ignore(repo: Path) -> None:
    (repo / ".gitignore").write_text("", encoding="utf-8")
    result = guard(repo)
    assert result.returncode == 1
    assert "not effectively ignored" in result.stdout


def test_absent_attachment_accepts_directory_ignore_rule(repo: Path) -> None:
    (repo / ".gitignore").write_text("/.agents/\n", encoding="utf-8")
    result = guard(repo)
    assert result.returncode == 0, result.stdout + result.stderr


def test_ignore_exception_is_not_an_effective_boundary(repo: Path) -> None:
    (repo / ".gitignore").write_text(
        "/.agents/*\n!/.agents/__tackrack_boundary_probe__\n", encoding="utf-8"
    )
    assert "not effectively ignored" in guard(repo).stdout


def test_independent_attachment_does_not_read_content(repo: Path) -> None:
    companion = repo / ".agents"
    companion.mkdir()
    git(companion, "init", "--quiet")
    (companion / "AGENTS.md").write_text("private instructions", encoding="utf-8")
    (companion / "unreadable").mkdir(mode=0)
    try:
        result = guard(repo)
    finally:
        (companion / "unreadable").chmod(0o700)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "content not read" in result.stdout
    assert "private instructions" not in result.stdout


@pytest.mark.parametrize(
    "kind", ["symlink", "file", "plain-directory", "shared-git", "shared-common"]
)
def test_invalid_attachment(repo: Path, tmp_path: Path, kind: str) -> None:
    companion = repo / ".agents"
    if kind == "symlink":
        companion.symlink_to(tmp_path, target_is_directory=True)
    elif kind == "file":
        companion.write_text("fixture", encoding="utf-8")
    else:
        companion.mkdir()
        if kind == "shared-git":
            (companion / ".git").write_text("gitdir: ../.git\n", encoding="utf-8")
        elif kind == "shared-common":
            git_dir = companion / ".git"
            git_dir.mkdir()
            (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (git_dir / "commondir").write_text("../../.git\n", encoding="utf-8")
    result = guard(repo)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL working: attachment" in result.stdout


def test_product_linked_worktree_is_supported(repo: Path, tmp_path: Path) -> None:
    git(repo, "add", ".gitignore", "pyproject.toml")
    git(repo, "commit", "--quiet", "-m", "initial")
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "--quiet", "-b", "linked", str(linked))
    result = guard(linked)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (linked / ".git").is_file()


def test_companion_linked_worktree_sharing_common_directory_is_rejected(repo: Path) -> None:
    git(repo, "add", ".gitignore", "pyproject.toml")
    git(repo, "commit", "--quiet", "-m", "initial")
    git(repo, "worktree", "add", "--quiet", "-b", "companion", str(repo / ".agents"))
    result = guard(repo)
    assert result.returncode == 1


@pytest.mark.parametrize("section", ["include", 'includeIf "gitdir:**"'])
def test_hostile_config_include_fails_closed_without_execution(
    repo: Path, tmp_path: Path, section: str
) -> None:
    marker = tmp_path / "executed"
    payload = tmp_path / "hostile-config"
    payload.write_text(f'[core]\nfsmonitor = sh -c "touch {marker}"\n', encoding="utf-8")
    with (repo / ".git" / "config").open("a", encoding="utf-8") as handle:
        handle.write(f"\n[{section}]\npath = {payload}\n")
    result = guard(repo)
    assert result.returncode == 2
    assert "includes are forbidden (not evaluated)" in result.stdout
    assert not marker.exists()


def test_hostile_fsmonitor_hook_and_environment_are_not_executed(
    repo: Path, tmp_path: Path
) -> None:
    marker = tmp_path / "executed"
    executable = tmp_path / "hostile"
    executable.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    executable.chmod(0o700)
    with (repo / ".git" / "config").open("a", encoding="utf-8") as handle:
        handle.write(f"\n[core]\nfsmonitor = {executable}\nhooksPath = {tmp_path}\n")
    result = guard(
        repo,
        environment={
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": str(executable),
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not marker.exists()


def test_positive_packaging_rejects_whole_repository(repo: Path) -> None:
    (repo / "pyproject.toml").write_text(
        PROJECT.replace('"/src/tackrack", "/tests", "/scripts", "/pyproject.toml"', '"/"'),
        encoding="utf-8",
    )
    assert "sdist requires an explicit product-owned include allowlist" in guard(repo).stdout


@pytest.mark.parametrize(
    "format,name",
    [
        ("zip", ".agents"),
        ("zip", "pkg/.agents/private.txt"),
        ("zip", "pkg/.git/config"),
        ("tar", "product/.agents/private.txt"),
        ("tar", "product/.git/HEAD"),
    ],
)
def test_all_archive_members_are_inspected(tmp_path: Path, format: str, name: str) -> None:
    artifact = tmp_path / ("product.whl" if format == "zip" else "product.tar.gz")
    if format == "zip":
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr("tackrack/__init__.py", "")
            archive.writestr(name, "fixture")
    else:
        with tarfile.open(artifact, "w:gz") as archive:
            entry = tarfile.TarInfo(name)
            data = b"fixture"
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    result = guard(tmp_path, "--artifact-mode", "--artifact", str(artifact))
    assert result.returncode == 1
    assert "forbidden member or link target" in result.stdout
    assert name in result.stdout
    assert not (tmp_path / name).exists()


def test_tar_link_into_companion_is_rejected(tmp_path: Path) -> None:
    artifact = tmp_path / "product.tar.gz"
    with tarfile.open(artifact, "w:gz") as archive:
        entry = tarfile.TarInfo("product/link")
        entry.type = tarfile.SYMTYPE
        entry.linkname = "../.agents/private"
        archive.addfile(entry)
    assert guard(tmp_path, "--artifact-mode", "--artifact", str(artifact)).returncode == 1


def test_repeatable_artifacts_and_explicit_git_unavailability(tmp_path: Path) -> None:
    wheel = tmp_path / "product.whl"
    sdist = tmp_path / "product.tar.gz"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("tackrack/__init__.py", "")
    with tarfile.open(sdist, "w:gz") as archive:
        archive.addfile(tarfile.TarInfo("product/src/tackrack"))
    result = guard(tmp_path, "--artifact-mode", "--artifact", str(wheel), "--artifact", str(sdist))
    assert result.returncode == 0
    assert "Git checks unavailable" in result.stdout
    assert "PASS artifact ownership" in result.stdout
    without_git = guard(tmp_path, "--artifact", str(wheel))
    assert without_git.returncode == 2
    assert "PASS product ownership" not in without_git.stdout


def test_artifact_mode_requires_an_artifact(tmp_path: Path) -> None:
    assert guard(tmp_path, "--artifact-mode").returncode == 1


def test_known_hosted_agent_caller_is_rejected_but_run_examples_are_not(repo: Path) -> None:
    path = repo / ".github/workflows/review.yml"
    path.parent.mkdir(parents=True)
    path.write_text(
        "jobs:\n  review:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n"
    )
    assert guard(repo).returncode == 1
    path.write_text(
        "jobs:\n  tests:\n    steps:\n      - run: |\n          echo 'uses: anthropics/claude-code-action@v1'\n"
    )
    assert guard(repo).returncode == 0
