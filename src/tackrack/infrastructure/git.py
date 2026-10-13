"""Read-only, bounded Git broker. Config includes fail closed before Git runs."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path


class GitError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def discover_root(path: Path) -> Path:
    path = path.resolve(strict=True)
    if not path.is_dir():
        raise GitError("not_a_directory")
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists() or (candidate / ".git").is_symlink():
            return candidate
    raise GitError("not_a_git_checkout")


def git_directories(root: Path) -> tuple[Path, Path]:
    marker = root / ".git"
    if marker.is_symlink():
        raise GitError("symlink_git_directory")
    if marker.is_dir():
        directory = marker.resolve()
    elif marker.is_file():
        if marker.stat().st_size > 4096:
            raise GitError("oversized_git_pointer")
        data = marker.read_bytes()
        if not data.startswith(b"gitdir: ") or b"\x00" in data:
            raise GitError("invalid_git_pointer")
        directory = (root / os.fsdecode(data[8:].strip())).resolve()
    else:
        raise GitError("missing_git_directory")
    common_pointer = directory / "commondir"
    common = directory
    if common_pointer.exists():
        if common_pointer.is_symlink() or common_pointer.stat().st_size > 4096:
            raise GitError("unsafe_common_directory_pointer")
        common = (directory / os.fsdecode(common_pointer.read_bytes().strip())).resolve()
    if not directory.is_dir() or not common.is_dir():
        raise GitError("missing_git_metadata")
    return directory, common


def validate_companion_metadata(root: Path) -> None:
    marker = root / ".git"
    if root.is_symlink() or marker.is_symlink() or not marker.is_dir():
        raise GitError("companion_git_directory_must_be_contained")
    common_pointer = marker / "commondir"
    if common_pointer.is_symlink() or common_pointer.exists():
        raise GitError("companion_linked_git_metadata_not_supported")
    for relative in ("objects", "objects/info", "refs"):
        if (marker / relative).is_symlink():
            raise GitError("companion_git_metadata_symlink")
    if (marker / "objects/info/alternates").is_symlink() or (
        marker / "objects/info/alternates"
    ).exists():
        raise GitError("companion_object_alternates_not_supported")


class GitBroker:
    _ALLOWED = {
        ("rev-parse", "--verify", "HEAD"),
        ("rev-parse", "--show-toplevel"),
        ("symbolic-ref", "--quiet", "--short", "HEAD"),
        ("rev-parse", "--show-object-format"),
        ("ls-files", "--stage", "-z"),
        ("ls-files", "--others", "--exclude-standard", "-z"),
        ("ls-files", "--others", "--ignored", "--exclude-standard", "-z"),
        ("ls-tree", "-r", "-z", "HEAD"),
        ("check-ignore", "--no-index", "-v", "-z", "--stdin"),
        ("config", "--local", "--null", "--get", "core.sparseCheckout"),
        ("config", "--local", "--null", "--get-regexp", r"^remote\..*\.url$"),
    }

    def __init__(self, root: Path) -> None:
        self.root = root
        self.directory, self.common = git_directories(root)
        self.configs: dict[str, bytes] = {}
        self.config_paths = [self.common / "config", self.directory / "config.worktree"]
        for base, name in ((self.common, "config"), (self.directory, "config.worktree")):
            path = base / name
            if path.exists():
                if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
                    raise GitError("unsafe_git_config")
                data = path.read_bytes()
                # Never allow Git to read arbitrary include/includeIf targets.
                if re.search(rb"(?im)^\s*\[\s*include(?:if)?(?:\s|\])", data):
                    raise GitError("git_config_includes_unsupported")
                self.configs[str(path)] = data
        binary = shutil.which("git", path="/usr/bin:/bin")
        if binary is None:
            raise GitError("git_binary_unavailable")
        self.binary = str(Path(binary).resolve())
        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent/tackrack-home",
            "XDG_CONFIG_HOME": "/nonexistent/tackrack-config",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
        self.prefix = [self.binary, "--no-pager", "--no-optional-locks"]
        for value in (
            "core.fsmonitor=false",
            "core.hooksPath=/dev/null",
            "core.untrackedCache=false",
            "core.preloadIndex=false",
            "maintenance.auto=false",
            "gc.auto=0",
            "core.pager=cat",
            "protocol.allow=never",
            "credential.helper=",
            "core.quotePath=true",
            "core.excludesFile=/dev/null",
        ):
            self.prefix += ["-c", value]
        self.prefix += ["-C", str(root)]
        reported = (
            self.run("rev-parse", "--show-toplevel")
            .removesuffix(b"\n")
            .decode("utf-8", "surrogateescape")
        )
        if Path(reported).resolve() != root.resolve():
            raise GitError("git_worktree_root_mismatch")

    def run(
        self, *args: str, allow_failure: bool = False, input_bytes: bytes | None = None
    ) -> bytes:
        allowed_blob = (
            len(args) == 3
            and args[0] == "cat-file"
            and args[1] in {"-s", "blob"}
            and re.fullmatch(r"[0-9a-f]{40,64}", args[2]) is not None
        )
        if args not in self._ALLOWED and not allowed_blob:
            raise GitError("git_command_not_allowed")
        # Fail if safety-screened configuration changes before invocation.
        if any(path.exists() and str(path) not in self.configs for path in self.config_paths):
            raise GitError("git_config_appeared_during_scan")
        for name, preimage in self.configs.items():
            path = Path(name)
            if path.is_symlink() or path.read_bytes() != preimage:
                raise GitError("git_config_changed")
        try:
            receipt = subprocess.run(
                self.prefix + list(args),
                input=input_bytes,
                env=self.env,
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitError("git_unavailable_or_timeout") from exc
        if receipt.returncode and not allow_failure:
            # Never echo arbitrary Git diagnostics, URLs or repository content.
            raise GitError("git_command_failed:" + args[0])
        return receipt.stdout if receipt.returncode == 0 else b""

    def blob(self, oid: str, limit: int) -> bytes | None:
        if not re.fullmatch(r"[0-9a-f]{40,64}", oid):
            raise GitError("invalid_git_object_id")
        size = self.run("cat-file", "-s", oid, allow_failure=True).strip()
        if not size.isdigit() or int(size) > limit:
            return None
        return self.run("cat-file", "blob", oid, allow_failure=True)

    def exclusion(self) -> tuple[bool, bytes]:
        data = self.run(
            "check-ignore",
            "--no-index",
            "-v",
            "-z",
            "--stdin",
            input_bytes=b".agents\x00",
            allow_failure=True,
        )
        fields = data.split(b"\x00")
        return bool(len(fields) >= 4 and fields[2] and not fields[2].startswith(b"!")), data

    def remotes(self) -> dict[str, str]:
        raw = self.run(
            "config", "--local", "--null", "--get-regexp", r"^remote\..*\.url$", allow_failure=True
        )
        result: dict[str, str] = {}
        for entry in raw.split(b"\x00"):
            if b"\n" in entry:
                key, value = entry.split(b"\n", 1)
                name = key.decode("utf-8", "replace")[7:-4]
                result[name] = value.decode("utf-8", "replace")
        return result
