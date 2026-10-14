#!/usr/bin/env python3
"""Passive product ownership checks; deliberately independent of TackRack."""

from __future__ import annotations

import argparse
import ast
import configparser
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

DISCOVERY_FILES = {"AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".mcp.json"}
DISCOVERY_DIRS = {".omp", ".codex", ".claude", ".cursor"}
METADATA_DIRS = {".git", ".venv", "__pycache__"}
ATTACHMENT = ".agents"
PATH_REFERENCE = re.compile(r"(?<![\w-])\.agents(?:[/\\\s\"'\]}),:]|$)")


@dataclass
class Report:
    findings: list[str] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def fail(self, layer: str, message: str) -> None:
        self.findings.append(f"{layer}: {message}")


def git_layout(root: Path) -> tuple[Path, Path]:
    """Read only repository pointers, never a repository's owned content."""
    marker = root / ".git"
    if marker.is_symlink():
        raise ValueError(".git must not be a symlink")
    if marker.is_dir():
        git_dir = marker.resolve()
    elif marker.is_file():
        text = marker.read_text(encoding="utf-8").strip()
        if not text.startswith("gitdir: ") or "\n" in text:
            raise ValueError("invalid .git pointer")
        git_dir = (root / text[8:]).resolve()
    else:
        raise ValueError("Git metadata is unavailable")
    if not git_dir.is_dir():
        raise ValueError("Git directory is unavailable")
    common_file = git_dir / "commondir"
    common_dir = git_dir
    if common_file.exists():
        if common_file.is_symlink() or not common_file.is_file():
            raise ValueError("invalid commondir pointer")
        pointer = common_file.read_text(encoding="utf-8").strip()
        if not pointer or "\n" in pointer:
            raise ValueError("invalid commondir pointer")
        common_dir = (git_dir / pointer).resolve()
    if not common_dir.is_dir():
        raise ValueError("Git common directory is unavailable")
    if not (common_dir / "objects").is_dir() or not (git_dir / "HEAD").is_file():
        raise ValueError("Git metadata is incomplete")
    return git_dir, common_dir


def safe_configuration(git_dir: Path, common_dir: Path) -> None:
    """Reject includes before Git can interpret them, including conditional includes."""
    for path in {common_dir / "config", git_dir / "config", git_dir / "config.worktree"}:
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unsafe Git configuration file: {path.name}")
        config = configparser.RawConfigParser(strict=False)
        try:
            config.read_string(path.read_text(encoding="utf-8"))
        except (configparser.Error, UnicodeError) as error:
            raise ValueError(f"cannot safely inspect Git configuration: {path.name}") from error
        for section in config.sections():
            lowered = section.lower().strip()
            if lowered == "include" or lowered.startswith("includeif "):
                raise ValueError("Git configuration includes are forbidden (not evaluated)")


class Git:
    def __init__(self, root: Path) -> None:
        executable = shutil.which("git", path=os.defpath)
        if executable is None:
            raise ValueError("trusted Git executable is unavailable")
        self.executable = str(Path(executable).resolve())
        self.root = root
        self.environment = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        self.environment.update(
            {
                "HOME": "/nonexistent/tackrack-boundary",
                "XDG_CONFIG_HOME": "/nonexistent/tackrack-boundary",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ATTR_NOSYSTEM": "1",
            }
        )

    def run(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                self.executable,
                "--no-pager",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.preloadIndex=false",
                "-c",
                "maintenance.auto=false",
                "-c",
                "gc.auto=0",
                "-c",
                "core.pager=cat",
                "-c",
                "protocol.allow=never",
                "-c",
                f"core.excludesFile={os.devnull}",
                "-C",
                str(self.root),
                *arguments,
            ],
            env=self.environment,
            capture_output=True,
            check=False,
            timeout=30,
        )


def reserved(path: str) -> bool:
    return path == ATTACHMENT or path.startswith(ATTACHMENT + "/")


def discovery_path(path: PurePosixPath) -> bool:
    if ".fixture." in path.name or path.name.endswith((".fixture", ".template")):
        return False
    return (
        path.name in DISCOVERY_FILES
        or any(part in DISCOVERY_DIRS for part in path.parts)
        or (
            ".github" in path.parts
            and (path.name == "copilot-instructions.md" or path.name.endswith(".instructions.md"))
        )
    )


def check_git(root: Path, report: Report) -> tuple[Path, Path] | None:
    try:
        layout = git_layout(root)
        safe_configuration(*layout)
        git = Git(root)
        toplevel = git.run("rev-parse", "--show-toplevel")
        if (
            toplevel.returncode
            or Path(os.fsdecode(toplevel.stdout.removesuffix(b"\n"))).resolve() != root.resolve()
        ):
            raise ValueError("Git working root differs from selected product")
        index = git.run("ls-files", "--stage", "-z")
        if index.returncode:
            raise ValueError("Git index inspection failed")
        for record in index.stdout.split(b"\0"):
            if not record:
                continue
            header, name = record.split(b"\t", 1)
            path = os.fsdecode(name)
            if reserved(path):
                report.fail(
                    "index",
                    f"reserved attachment tracked: {path!r} (mode {header.split()[0].decode()})",
                )
            elif discovery_path(PurePosixPath(path)):
                report.fail("index", f"live agent discovery path outside attachment: {path!r}")
        head = git.run("rev-parse", "--verify", "--quiet", "HEAD")
        if head.returncode == 0:
            tree = git.run("ls-tree", "-r", "-t", "-z", "--full-tree", "HEAD")
            if tree.returncode:
                raise ValueError("committed tree inspection failed")
            for record in tree.stdout.split(b"\0"):
                if not record:
                    continue
                header, name = record.split(b"\t", 1)
                path = os.fsdecode(name)
                if reserved(path):
                    report.fail(
                        "committed",
                        f"reserved attachment tracked: {path!r} (mode {header.split()[0].decode()})",
                    )
                elif discovery_path(PurePosixPath(path)):
                    report.fail(
                        "committed", f"live agent discovery path outside attachment: {path!r}"
                    )
        elif head.returncode != 1:
            raise ValueError("HEAD inspection failed")
        else:
            symbolic = git.run("symbolic-ref", "--quiet", "HEAD")
            if symbolic.returncode or not symbolic.stdout.startswith(b"refs/"):
                raise ValueError("HEAD is neither a commit nor an unborn symbolic branch")
            report.notes.append("committed: no HEAD yet; index inspected")
        attachment = root / ATTACHMENT
        ignore_paths = (
            (ATTACHMENT,)
            if attachment.is_symlink() or attachment.is_file()
            else (ATTACHMENT + "/", ATTACHMENT + "/__tackrack_boundary_probe__")
        )
        for path in ignore_paths:
            ignored = git.run("check-ignore", "--no-index", "-q", "--", path)
            if ignored.returncode == 1:
                report.fail("working", f"reserved attachment is not effectively ignored: {path!r}")
            elif ignored.returncode != 0:
                raise ValueError("effective ignore inspection failed")
        return layout
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.unavailable.append(f"Git checks unavailable: {error}")
        return None


def check_attachment(root: Path, product: tuple[Path, Path] | None, report: Report) -> None:
    attachment = root / ATTACHMENT
    if not attachment.exists() and not attachment.is_symlink():
        report.notes.append("working: optional attachment absent")
        return
    if attachment.is_symlink() or not attachment.is_dir():
        report.fail("working", "attachment must be a real directory, not a symlink or file")
        return
    try:
        marker = attachment / ".git"
        if marker.is_symlink() or not marker.is_dir():
            raise ValueError("attachment Git metadata must be contained at .agents/.git")
        if (marker / "commondir").is_symlink() or (marker / "commondir").exists():
            raise ValueError("linked companion Git metadata is not supported")
        companion = git_layout(attachment)
        if (companion[1] / "objects/info/alternates").exists():
            raise ValueError("companion object alternates are not independent")
        if product is None:
            report.unavailable.append(
                "attachment independence unavailable without product Git metadata"
            )
        elif set(companion) & set(product):
            report.fail("working", "attachment shares product Git or common directory")
        elif any(
            directory.is_relative_to(root) and not directory.is_relative_to(attachment)
            for directory in companion
        ):
            report.fail("working", "attachment Git metadata belongs to the product tree")
        else:
            report.notes.append("working: independent attachment metadata (content not read)")
    except (OSError, ValueError) as error:
        report.fail("working", f"attachment is not an independent Git repository: {error}")


def inert(path: Path) -> bool:
    return ".fixture." in path.name or path.name.endswith((".fixture", ".template"))


def active_python(text: str) -> bool:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    nodes = list(ast.walk(tree))
    aliases: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "agents":
                    return True
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.split(".")[0] == "agents":
                return True
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{module}.{alias.name}"

    def qualified(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return qualified(node.value) + "." + node.attr
        return ""

    tainted: set[str] = set()

    def companion_reference(node: ast.AST) -> bool:
        return any(
            (
                isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                and bool(PATH_REFERENCE.search(value.value))
            )
            or (isinstance(value, ast.Name) and value.id in tainted)
            for value in ast.walk(node)
        )

    # Propagate static path bindings only; ordinary detector constants remain inert
    # unless they reach an execution, import, or test discovery sink.
    changed = True
    while changed:
        changed = False
        for node in nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if companion_reference(node.value):
                    for target in targets:
                        if isinstance(target, ast.Name) and target.id not in tainted:
                            tainted.add(target.id)
                            changed = True
                        elif qualified(target) == "sys.path":
                            return True
            elif isinstance(node, ast.AugAssign):
                if qualified(node.target) == "sys.path" and companion_reference(node.value):
                    return True
    sinks = {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.execv",
        "os.execve",
        "runpy.run_path",
        "importlib.import_module",
        "importlib.util.spec_from_file_location",
        "importlib.machinery.SourceFileLoader",
        "sys.path.append",
        "sys.path.insert",
        "sys.path.extend",
        "site.addsitedir",
        "pytest.main",
        "unittest.defaultTestLoader.discover",
        "exec",
        "eval",
        "compile",
    }
    return any(
        isinstance(node, ast.Call)
        and qualified(node.func) in sinks
        and any(
            companion_reference(argument)
            for argument in [*node.args, *(keyword.value for keyword in node.keywords)]
        )
        for node in nodes
    )


def active_commands(path: Path, text: str) -> bool:
    if path.suffix in {".yml", ".yaml"}:
        block_indent: int | None = None
        for line in text.splitlines():
            content = line.lstrip()
            if not content or content.startswith("#"):
                continue
            indent = len(line) - len(content)
            if block_indent is not None and indent <= block_indent:
                block_indent = None
            if block_indent is None and re.match(
                r"""(?:-\s*)?uses\s*:\s*["']?(?:anthropics/claude-code-action|openai/codex-action)@""",
                content,
                re.IGNORECASE,
            ):
                return True
            if re.match(r"(?:-\s*)?(run|env)\s*:", content):
                block_indent = indent
            if block_indent is not None or re.match(
                r"(?:-\s*)?(uses|working-directory)\s*:", content
            ):
                if PATH_REFERENCE.search(content.split("#", 1)[0]):
                    return True
        return False
    return any(PATH_REFERENCE.search(line.split("#", 1)[0]) for line in text.splitlines())


def check_working(root: Path, report: Report) -> None:
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = list(directory.iterdir())
        except OSError as error:
            report.fail("working", f"cannot inspect {directory.relative_to(root)}: {error}")
            continue
        for path in entries:
            relative = path.relative_to(root)
            if relative.parts[0] == ATTACHMENT or path.name in METADATA_DIRS:
                continue
            if inert(path):
                continue
            if discovery_path(PurePosixPath(relative.as_posix())):
                report.fail(
                    "working",
                    f"live agent discovery path outside attachment: {relative.as_posix()!r}",
                )
                if path.is_dir():
                    continue
            if path.is_symlink():
                continue
            if path.is_dir():
                stack.append(path)
            elif path.is_file():
                python = path.suffix == ".py"
                commands = (
                    path.suffix == ".sh"
                    or path.name in {"Makefile", "tox.ini", "setup.cfg"}
                    or (
                        relative.parts[:2] == (".github", "workflows")
                        and path.suffix in {".yml", ".yaml"}
                    )
                    or path.name.startswith("requirements")
                )
                if not (python or commands):
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                    depends = active_python(text) if python else active_commands(path, text)
                except (OSError, UnicodeError) as error:
                    report.fail("working", f"cannot inspect active code {relative}: {error}")
                    continue
                if depends:
                    report.fail("working", f"active companion dependency: {relative.as_posix()!r}")


def check_packaging(root: Path, report: Report) -> None:
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        build = project.get("tool", {}).get("hatch", {}).get("build", {})
        targets = build.get("targets", {})
        if targets.get("wheel", {}).get("packages") != ["src/tackrack"]:
            report.fail("packaging", "wheel must positively select only src/tackrack")
        sdist = targets.get("sdist", {})
        allowed = {
            "src/tackrack",
            "tests",
            "scripts",
            "docs",
            "README.md",
            "pyproject.toml",
            "uv.lock",
            "LICENSE",
            "LICENSE.txt",
            "CHANGELOG.md",
            ".gitignore",
        }
        include = sdist.get("include", [])
        if (
            not isinstance(include, list)
            or not include
            or "src/tackrack" not in {str(item).strip("/") for item in include}
            or any(str(item).strip("/") not in allowed for item in include)
        ):
            report.fail("packaging", "sdist requires an explicit product-owned include allowlist")
        exclude = {str(item).strip("/") for item in sdist.get("exclude", [])}
        if not {".agents", ".git", ".venv"}.issubset(exclude):
            report.fail("packaging", "sdist must explicitly exclude .agents, .git and .venv")
        active = [
            project.get("build-system", {}),
            project.get("dependency-groups", {}),
            project.get("project", {}).get("dependencies", []),
            project.get("project", {}).get("optional-dependencies", {}),
            project.get("project", {}).get("scripts", {}),
            {
                key: value
                for key, value in project.get("tool", {}).items()
                if key in {"hatch", "pytest", "mypy", "uv", "setuptools", "pdm", "poetry"}
            },
        ]

        # Exclusion declarations are boundaries, not dependencies.
        def references(value: object, key: str = "") -> bool:
            if key in {"exclude", "extend-exclude"}:
                return False
            if isinstance(value, dict):
                return any(references(child, str(name)) for name, child in value.items())
            if isinstance(value, list):
                return any(references(child, key) for child in value)
            return isinstance(value, str) and bool(PATH_REFERENCE.search(value))

        if any(references(item) for item in active):
            report.fail("working", "active companion dependency in pyproject.toml")
    except (OSError, ValueError, TypeError, AttributeError) as error:
        report.fail("packaging", f"cannot inspect positive packaging contract: {error}")


def check_artifact(path: Path, report: Report) -> None:
    def member(name: str, link: str = "") -> None:
        for value in (name, link):
            parts = PurePosixPath(value.replace("\\", "/")).parts
            if ATTACHMENT in parts or ".git" in parts:
                report.fail("artifact", f"{path.name}: forbidden member or link target {value!r}")

    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for entry in archive.infolist():
                    member(entry.filename)
                    if stat.S_ISLNK(entry.external_attr >> 16):
                        member(
                            entry.filename, archive.read(entry).decode("utf-8", "surrogateescape")
                        )
        elif tarfile.is_tarfile(path):
            with tarfile.open(path, mode="r:*") as archive:
                for entry in archive:
                    member(entry.name, entry.linkname if entry.issym() or entry.islnk() else "")
        else:
            report.fail("artifact", f"unsupported or invalid archive: {path}")
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, RuntimeError) as error:
        report.fail("artifact", f"cannot inspect {path}: {error}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--artifact", type=Path, action="append", default=[])
    parser.add_argument(
        "--artifact-mode",
        action="store_true",
        help="inspect artifacts without Git or a checkout; explicitly reports Git as unavailable",
    )
    arguments = parser.parse_args(argv)
    report = Report()
    if arguments.artifact_mode:
        report.notes.append(
            "Git checks unavailable: explicit artifact-only mode (not a Git boundary pass)"
        )
        if not arguments.artifact:
            report.fail("artifact", "artifact-only mode requires at least one --artifact")
    else:
        root = arguments.root.resolve()
        layout = check_git(root, report)
        check_attachment(root, layout, report)
        check_working(root, report)
        check_packaging(root, report)
    for artifact in arguments.artifact:
        check_artifact(artifact, report)
    for message in report.notes:
        print(f"INFO {message}")
    for message in report.findings:
        print(f"FAIL {message}")
    for message in report.unavailable:
        print(f"UNAVAILABLE {message}")
    if report.unavailable:
        return 2
    if report.findings:
        return 1
    print(
        "PASS artifact ownership" if arguments.artifact_mode else "PASS product ownership boundary"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
