from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def private_user_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for category in ("CONFIG", "STATE", "CACHE"):
        monkeypatch.setenv(f"TACKRACK_{category}_DIR", str(tmp_path / category.lower()))
    monkeypatch.delenv("TACKRACK_GITHUB_TOKEN", raising=False)


def git(root: Path, *args: str) -> bytes:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root.parent / "empty-home"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@invalid.example",
        "GIT_COMMITTER_NAME": "Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@invalid.example",
    }
    return subprocess.check_output(
        ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args], env=env
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "product"
    root.mkdir()
    git(root, "init", "--template=", "--initial-branch=main")
    (root / ".gitignore").write_text("/.agents\n/AGENTS.md\n/ignored/\n", encoding="utf-8")
    return root
