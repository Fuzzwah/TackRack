"""Ownership-aware collection. Repository content is data, never executable policy."""

from __future__ import annotations

import base64
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from tackrack.domain.models import (
    CollectionResult,
    Coverage,
    EvidenceRecord,
    FileEntry,
    Snapshot,
    SourceDescriptor,
    canonical_digest,
    digest_bytes,
    utc_now,
)
from tackrack.infrastructure.git import GitBroker, GitError
from tackrack.infrastructure.redaction import sanitize
from tackrack.plugins.contracts import (
    CollectionRequest,
    SourceContext,
    SourceProbeRequest,
    SourceProbeResult,
)

MAX_PATHS = 100_000
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
ACTIVE_NAMES = {
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursorrules",
    ".mcp.json",
    "copilot-instructions.md",
}
ACTIVE_DIRS = {".omp", ".codex", ".claude", ".cursor"}
IGNORED_DISCOVERY = (
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursorrules",
    ".mcp.json",
    ".omp",
    ".codex",
    ".claude",
    ".cursor",
    ".github/copilot-instructions.md",
    ".github/instructions",
)
SKIP_COMPANION = {
    ".git",
    ".local",
    ".venv",
    "node_modules",
    "__pycache__",
    ".cache",
    "sessions",
    "transcripts",
    "credentials",
    ".ssh",
    "cache",
    "logs",
    "raw-sessions",
    "private",
    "secrets",
}
COMPANION_DIRS = {
    "policy",
    "profiles",
    "shipping",
    "skills",
    "skill-sources",
    "instructions",
    "tools",
    "bootstrap",
} | ACTIVE_DIRS
COMPANION_FILES = {
    "project.toml",
    "README.md",
    ".gitignore",
    "tackrack.lock.json",
    "policy.toml",
    "shipping.toml",
} | ACTIVE_NAMES


def credential_path(path: str) -> bool:
    """Credential filenames and private credential directories have no exportable identity."""
    return any(
        part.lower() in {".env", "auth.json", "credentials", "credentials.json", "secrets", ".ssh"}
        or part.lower().startswith((".env.", "credentials."))
        for part in Path(path).parts
    )


def companion_content(path: str, full: bool) -> bool:
    parts = Path(path).parts
    if (
        any(part in SKIP_COMPANION for part in parts)
        or credential_path(path)
        or Path(path).name.lower()
        in {
            "sessions.json",
            "transcripts.json",
        }
    ):
        return False
    return full or parts[0] in COMPANION_DIRS or (len(parts) == 1 and parts[0] in COMPANION_FILES)


def reserved(path: str) -> bool:
    return path == ".agents" or path.startswith(".agents/")


def embedded_content(path: str) -> bool:
    """Only authored companion surfaces are collected from ordinary .agents trees."""
    parts = Path(path).parts
    if ".agents" not in parts:
        return True
    offset = parts.index(".agents")
    relative = Path(*parts[offset + 1 :])
    return bool(relative.parts) and companion_content(str(relative), False)


def active_path(path: str) -> bool:
    if Path(path).name.endswith((".template", ".fixture.json")):
        return False
    parts = Path(path).parts
    return (
        Path(path).name in ACTIVE_NAMES
        or any(p in ACTIVE_DIRS for p in parts)
        or (path.startswith(".github/instructions/") and path.endswith(".instructions.md"))
        or (".agents" in parts and "skills" in parts and Path(path).name == "SKILL.md")
    )


def display_path(path: bytes) -> str:
    # Escaped display plus base64 preserve non-UTF8 and hostile-control path identity.
    decoded = os.fsdecode(path)
    return (
        decoded.encode("unicode_escape").decode("ascii")
        if any(ord(c) < 32 or 127 <= ord(c) < 160 or 0xD800 <= ord(c) <= 0xDFFF for c in decoded)
        else decoded
    )


def path_record(raw: bytes, revision: str, mode: str, **kwargs: Any) -> FileEntry:
    return FileEntry(
        path=display_path(raw),
        path_bytes=base64.b64encode(raw).decode(),
        revision=revision,
        mode=mode,
        **kwargs,
    )


def evidence_for(entry: FileEntry, data: bytes, scope: str, kind: str = "file") -> EvidenceRecord:
    original_text = data.decode("utf-8", "replace")
    text, redacted = sanitize(original_text)
    sensitive_name = credential_path(entry.path)
    redacted |= sensitive_name
    # Sensitive payloads are never exported, including guessable value hashes.
    digest = "private-sensitive-content" if redacted else digest_bytes(data)
    if redacted:
        text = "[Sensitive payload withheld]"
        entry.digest = digest
        entry.object_id = None
    return EvidenceRecord(
        evidence_id=canonical_digest(
            [scope, entry.path_bytes, entry.revision, entry.stage, digest]
        ),
        source_id="local-git",
        kind=kind,
        scope=scope,
        revision=entry.revision,
        path=entry.path,
        path_bytes=entry.path_bytes,
        digest=digest,
        collected_at=utc_now(),
        excerpt=text[:8192],
        byte_end=len(data),
        truncated=len(text) > 8192,
        sensitivity="sensitive" if redacted else "ordinary",
        redacted=redacted,
        payload={
            "mode": entry.mode,
            "stage": entry.stage,
            "object_id": entry.object_id,
            "exact_utf8_excerpt": not redacted and text == original_text,
            "content_identity_withheld": redacted,
        },
    )


Stamp = tuple[int, int, int, int]


def stamp(path: Path) -> Stamp | None:
    try:
        metadata = path.lstat()
        return metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_mode
    except FileNotFoundError:
        return None


def link_parent(path: Path, root: Path) -> bool:
    return any(
        parent.is_symlink()
        for parent in reversed(path.parents)
        if parent != root and parent.is_relative_to(root)
    )


@dataclass
class SnapshotProbe:
    """Private fresh-scan witnesses; never serialized or accepted as saved-report freshness."""

    root: Path
    observations: list[tuple[Path, Stamp | None]] = field(default_factory=list)
    index: bytes | None = None
    untracked: bytes = b""
    head: str | None = None
    branch: str | None = None
    common: str | None = None
    configs: dict[str, bytes] = field(default_factory=dict)
    ignored_discovery: bytes = b""
    discovery_patterns: tuple[str, ...] = ()

    def observe(self, path: Path) -> None:
        if not link_parent(path, self.root):
            self.observations.append((path, stamp(path)))

    def changed(self) -> bool:
        try:
            for path, before in self.observations:
                if link_parent(path, self.root) or stamp(path) != before:
                    return True
            for name, data in self.configs.items():
                path = Path(name)
                if path.is_symlink() or path.stat().st_size > MAX_FILE or path.read_bytes() != data:
                    return True
            if self.index is not None:
                broker = GitBroker(self.root)
                if str(broker.common) != self.common:
                    return True
                if broker.run("ls-files", "--stage", "-z") != self.index:
                    return True
                if broker.run("ls-files", "--others", "--exclude-standard", "-z") != self.untracked:
                    return True
                if (
                    self.discovery_patterns
                    and broker.run(
                        "ls-files",
                        "--others",
                        "--ignored",
                        "--exclude-standard",
                        "-z",
                        "--",
                        *self.discovery_patterns,
                    )
                    != self.ignored_discovery
                ):
                    return True
                head = (
                    broker.run("rev-parse", "--verify", "HEAD", allow_failure=True)
                    .strip()
                    .decode("ascii")
                    or None
                )
                branch = (
                    broker.run("symbolic-ref", "--quiet", "--short", "HEAD", allow_failure=True)
                    .decode()
                    .strip()
                    or None
                )
                return head != self.head or branch != self.branch
        except (OSError, GitError):
            return True
        return False


def bounded_walk(
    root: Path,
    scope: str,
    full: bool,
    probe: SnapshotProbe | None = None,
    *,
    agents_mode: Literal["boundary", "embedded", "none"] = "boundary",
) -> tuple[list[bytes], list[str]]:
    paths: list[bytes] = []
    reasons: list[str] = []
    stack = [root]
    visited = 0
    while stack:
        folder = stack.pop()
        try:
            if probe:
                probe.observe(folder)
            children = sorted(os.scandir(folder), key=lambda e: os.fsencode(e.name))
        except OSError:
            reasons.append("inaccessible_directory")
            continue
        for item in children:
            visited += 1
            if visited > MAX_PATHS:
                return paths, reasons + ["path_limit"]
            path = Path(item.path)
            rel = path.relative_to(root)
            parts = rel.parts
            if item.name == ".git" or (scope == "workbench" and item.name in SKIP_COMPANION):
                if scope == "workbench":
                    reasons.append("companion_content_excluded")
                continue
            if scope == "project" and parts[0] == ".agents":
                if agents_mode != "embedded":
                    continue
                if len(parts) > 1 and not embedded_content(str(rel)):
                    reasons.append("embedded_agents_content_excluded")
                    continue
            if scope == "workbench" and not companion_content(str(rel), full):
                reasons.append("companion_content_excluded")
                continue
            if len(paths) >= MAX_PATHS:
                return paths, reasons + ["path_limit"]
            if item.is_dir(follow_symlinks=False):
                if (path / ".git").exists() or (path / ".git").is_symlink():
                    paths.append(os.fsencode(str(rel)))
                    reasons.append("nested_repository_not_recursed")
                    continue
                if len(parts) > 16:
                    reasons.append("depth_limit")
                    continue
                stack.append(path)
            else:
                paths.append(os.fsencode(str(rel)))
    return sorted(set(paths)), sorted(set(reasons))


class LocalGitSource:
    def describe(self) -> SourceDescriptor:
        return SourceDescriptor(
            plugin_id="local-git",
            capabilities=["git_state", "local_content", "attachment_boundary"],
            permissions=["read:approved-checkout"],
        )

    def probe(self, request: SourceProbeRequest) -> SourceProbeResult:
        return SourceProbeResult(
            eligible=(request.root / ".git").exists(), reason="local checkout metadata only"
        )

    def collect(self, request: CollectionRequest, context: SourceContext) -> CollectionResult:
        _, result = collect_snapshot(request.root)
        return result


def collect_snapshot(
    root: Path,
    scope: str = "project",
    *,
    full: bool = False,
    include_ignored: bool = False,
    git_enabled: bool = True,
    agents_mode: Literal["boundary", "embedded", "none"] = "boundary",
    probe: SnapshotProbe | None = None,
) -> tuple[Snapshot, CollectionResult]:
    snapshot = Snapshot(
        root=str(root),
        scope={
            "namespace": scope,
            "max_paths": MAX_PATHS,
            "max_file_bytes": MAX_FILE,
            "max_total_text_bytes": MAX_TOTAL,
            "include_ignored": include_ignored,
            "ordinary_ignored": "excluded" if not include_ignored else "included",
            "known_ignored_discovery": list(IGNORED_DISCOVERY) if scope == "project" else [],
            "companion_runtime_exclusions": sorted(SKIP_COMPANION) if scope == "workbench" else [],
            "full_companion": full,
            "agents_mode": agents_mode,
            "embedded_agents_content": "known authored paths only",
            "embedded_agents_exclusions": sorted(SKIP_COMPANION),
            "sensitive_content_identity": "raw digests withheld; fingerprint is not an extraction precondition",
        },
    )
    result = CollectionResult()
    reasons: list[str] = []
    broker: GitBroker | None = None
    initial_git = b""
    initial_untracked = b""
    initial_discovery = b""
    discovery_patterns: tuple[str, ...] = ()
    git_entries: list[FileEntry] = []
    working_paths: set[bytes] = set()
    if probe:
        probe.observe(root)
    if git_enabled:
        try:
            broker = GitBroker(root)
            snapshot.git_common_dir = str(broker.common)
            head = broker.run("rev-parse", "--verify", "HEAD", allow_failure=True).strip()
            snapshot.head = head.decode("ascii") or None
            snapshot.branch = (
                broker.run("symbolic-ref", "--quiet", "--short", "HEAD", allow_failure=True)
                .decode()
                .strip()
                or None
            )
            snapshot.object_format = (
                broker.run("rev-parse", "--show-object-format").decode().strip()
            )
            initial_git = broker.run("ls-files", "--stage", "-z")
            for row in initial_git.split(b"\x00"):
                if not row:
                    continue
                meta, raw = row.split(b"\t", 1)
                mode, oid, stage = meta.decode("ascii").split()
                git_entries.append(path_record(raw, "index", mode, object_id=oid, stage=int(stage)))
                working_paths.add(raw)
                if stage != "0":
                    reasons.append("merge_conflicts")
            if snapshot.head:
                for row in broker.run("ls-tree", "-r", "-z", "HEAD").split(b"\x00"):
                    if not row:
                        continue
                    meta, raw = row.split(b"\t", 1)
                    mode, _, oid = meta.decode("ascii").split()
                    git_entries.append(path_record(raw, "head", mode, object_id=oid))
            initial_untracked = broker.run("ls-files", "--others", "--exclude-standard", "-z")
            working_paths.update(p for p in initial_untracked.split(b"\x00") if p)
            if include_ignored:
                working_paths.update(
                    p
                    for p in broker.run(
                        "ls-files", "--others", "--ignored", "--exclude-standard", "-z"
                    ).split(b"\x00")
                    if p
                )
            sparse = broker.run(
                "config", "--local", "--null", "--get", "core.sparseCheckout", allow_failure=True
            )
            if sparse.strip(b"\x00\n").lower() == b"true":
                reasons.append("sparse_checkout")
            # Config is provenance data; URLs/credentials remain redacted.
            for name, data in broker.configs.items():
                entry = path_record(os.fsencode(Path(name).name), "metadata", "100644")
                result.evidence.append(evidence_for(entry, data, scope, "git_config"))
        except (GitError, OSError, ValueError) as exc:
            reasons.append(exc.reason if isinstance(exc, GitError) else "git_metadata_error")
            broker = None
    if broker is None and scope == "project" and include_ignored:
        walked, walk_reasons = bounded_walk(root, scope, full, probe, agents_mode=agents_mode)
        working_paths.update(walked)
        reasons.extend(walk_reasons)
    elif broker is None:
        # Without safe Git ignore metadata, do not enumerate arbitrary ignored content.
        working_paths.update(
            os.fsencode(name)
            for name in ("README.md", ".gitignore", "pyproject.toml")
            if (root / name).is_file() and not (root / name).is_symlink()
        )
    if scope == "project":
        agents_roots: set[str] = set()
        excluded_agents_roots: set[str] = set()
        if agents_mode == "embedded":
            agents_roots.add(".agents")
            if broker:
                # Git enumerates only known discovery surfaces, not arbitrary ignored files.
                discovery_patterns = tuple(
                    f":(glob)**/.agents/{name}/**" for name in sorted(COMPANION_DIRS)
                ) + tuple(f":(glob)**/.agents/{name}" for name in sorted(COMPANION_FILES))
                initial_discovery = broker.run(
                    "ls-files",
                    "--others",
                    "--ignored",
                    "--exclude-standard",
                    "-z",
                    "--",
                    *discovery_patterns,
                )
                for raw in initial_discovery.split(b"\x00"):
                    if raw and embedded_content(os.fsdecode(raw)):
                        working_paths.add(raw)
            for raw in working_paths | {
                base64.b64decode(entry.path_bytes) for entry in git_entries
            }:
                parts = Path(os.fsdecode(raw)).parts
                if ".agents" in parts:
                    agents_roots.add(str(Path(*parts[: parts.index(".agents") + 1])))
        for relative in sorted(agents_roots):
            path = root / relative
            if link_parent(path, root):
                reasons.append("symlink_parent_not_followed")
                continue
            if probe:
                probe.observe(path)
            if path.is_symlink():
                working_paths.add(os.fsencode(relative))
                reasons.append("embedded_agents_symlink_not_followed")
            elif path.is_dir():
                if probe:
                    probe.observe(path / ".git")
                if (path / ".git").exists() or (path / ".git").is_symlink():
                    reasons.append("nested_repository_not_recursed")
                    excluded_agents_roots.add(relative)
                    continue
                candidates, walk_reasons = bounded_walk(path, "workbench", False, probe)
                working_paths.update(os.fsencode(relative) + b"/" + p for p in candidates)
                reasons.extend(walk_reasons)
        for relative in IGNORED_DISCOVERY:
            path = root / relative
            if link_parent(path, root):
                continue
            if probe:
                probe.observe(path)
            # Known bounded ignored paths are inspected without following links.
            if not path.is_symlink() and path.is_dir():
                candidates, walk_reasons = bounded_walk(path, "workbench", True, probe)
                working_paths.update(os.fsencode(relative) + b"/" + p for p in candidates)
                reasons.extend(walk_reasons)
            elif path.exists() or path.is_symlink():
                working_paths.add(os.fsencode(relative))
    else:
        walked, walk_reasons = bounded_walk(root, scope, full, probe)
        working_paths.update(walked)
        reasons.extend(walk_reasons)
    total = 0
    # Index leak metadata is independent of authorised embedded content collection.
    for entry in git_entries[:MAX_PATHS]:
        snapshot.entries.append(entry)
        rel = os.fsdecode(base64.b64decode(entry.path_bytes))
        if scope == "project" and ".agents" in Path(rel).parts and credential_path(rel):
            entry.object_id = None
            entry.digest = "private-sensitive-content"
            reasons.append("sensitive_content_identity_withheld")
        if reserved(rel) and scope == "project":
            result.evidence.append(
                evidence_for(
                    entry, b"Product Git owns reserved attachment path", scope, "index_leak"
                )
            )
            if agents_mode != "embedded":
                continue
        if scope == "project" and any(
            rel == name or rel.startswith(name + "/") for name in excluded_agents_roots
        ):
            continue
        if scope == "project" and ".git" in Path(rel).parts:
            reasons.append("git_metadata_path_excluded")
            continue
        if scope == "project" and ".agents" in Path(rel).parts and not embedded_content(rel):
            if agents_mode == "embedded":
                reasons.append("embedded_agents_content_excluded")
            continue
        if scope == "workbench" and not companion_content(entry.path, full):
            continue
        if broker and entry.mode != "160000" and total < MAX_TOTAL:
            assert entry.object_id is not None
            blob_data = broker.blob(entry.object_id, min(MAX_FILE, MAX_TOTAL - total))
            if blob_data is None:
                reasons.append("missing_or_large_git_object")
                continue
            total += len(blob_data)
            entry.digest = digest_bytes(blob_data)
            result.evidence.append(evidence_for(entry, blob_data, scope))
    if len(git_entries) > MAX_PATHS or len(working_paths) > MAX_PATHS:
        reasons.append("path_limit")
    observations: list[tuple[Path, tuple[int, int, int, int]]] = []
    for raw in sorted(working_paths)[:MAX_PATHS]:
        rel = os.fsdecode(raw)
        if scope == "project" and any(
            rel == name or rel.startswith(name + "/") for name in excluded_agents_roots
        ):
            continue
        if scope == "project" and reserved(rel) and agents_mode != "embedded":
            continue
        if scope == "project" and ".git" in Path(rel).parts:
            reasons.append("git_metadata_path_excluded")
            continue
        if scope == "project" and ".agents" in Path(rel).parts and not embedded_content(rel):
            if agents_mode == "embedded":
                reasons.append("embedded_agents_content_excluded")
            continue
        if scope == "workbench" and not companion_content(rel, full):
            continue
        path = root / rel
        if link_parent(path, root):
            reasons.append("symlink_parent_not_followed")
            continue
        if probe:
            probe.observe(path)
        try:
            st = path.lstat()
            stamp = (st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode)
            observations.append((path, stamp))
            if stat.S_ISLNK(st.st_mode):
                data = os.fsencode(os.readlink(path))
                entry = path_record(
                    raw,
                    "working",
                    "120000",
                    size=len(data),
                    digest=digest_bytes(data),
                    link_target=display_path(data),
                )
                snapshot.entries.append(entry)
                result.evidence.append(evidence_for(entry, data, scope, "symlink"))
                continue
            if stat.S_ISDIR(st.st_mode):
                snapshot.entries.append(path_record(raw, "working", "040000"))
                reasons.append("nested_repository_not_recursed")
                continue
            if not stat.S_ISREG(st.st_mode):
                reasons.append("special_file_not_read")
                continue
            entry = path_record(
                raw, "working", "100755" if st.st_mode & 0o111 else "100644", size=st.st_size
            )
            snapshot.entries.append(entry)
            if st.st_size > MAX_FILE or total + st.st_size > MAX_TOTAL:
                reasons.append("file_or_total_size_limit")
                continue
            # O_NOFOLLOW closes the final-component symlink race; ancestor races remain documented.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                data = stream.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                reasons.append("file_size_changed")
                continue
            total += len(data)
            entry.digest = digest_bytes(data)
            if b"\x00" in data[:8192]:
                continue
            result.evidence.append(evidence_for(entry, data, scope))
        except FileNotFoundError:
            snapshot.entries.append(path_record(raw, "working", "deleted"))
        except OSError:
            reasons.append("file_unavailable")
    changed = False
    for path, before in observations:
        try:
            st = path.lstat()
            changed |= before != (st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode)
        except OSError:
            changed = True
    if broker:
        try:
            changed |= broker.run("ls-files", "--stage", "-z") != initial_git
            changed |= (
                broker.run("ls-files", "--others", "--exclude-standard", "-z") != initial_untracked
            )
            if discovery_patterns:
                changed |= (
                    broker.run(
                        "ls-files",
                        "--others",
                        "--ignored",
                        "--exclude-standard",
                        "-z",
                        "--",
                        *discovery_patterns,
                    )
                    != initial_discovery
                )
            current_head = (
                broker.run("rev-parse", "--verify", "HEAD", allow_failure=True)
                .strip()
                .decode("ascii")
                or None
            )
            changed |= current_head != snapshot.head
        except GitError:
            changed = True
    # Deliberate scope/privacy boundaries are not missing authorised coverage.
    scope_exclusions = {
        "embedded_agents_content_excluded",
        "companion_content_excluded",
        "git_metadata_path_excluded",
        "sensitive_content_identity_withheld",
    }
    snapshot.scope["exclusion_diagnostics"] = sorted(set(reasons) & scope_exclusions)
    reasons = [reason for reason in reasons if reason not in scope_exclusions]
    snapshot.reasons = sorted(set(reasons + (["changed_during_scan"] if changed else [])))
    snapshot.status = "changed_during_scan" if changed else "incomplete" if reasons else "stable"
    snapshot.entries.sort(key=lambda e: (e.path_bytes, e.revision, e.stage))
    snapshot.fingerprint = canonical_digest(
        {
            "head": snapshot.head,
            "branch": snapshot.branch,
            "object_format": snapshot.object_format,
            "entries": [e.model_dump() for e in snapshot.entries],
            "scope": snapshot.scope,
        }
    )
    snapshot.ended_at = utc_now()
    if probe:
        probe.observations.extend(observations)
        if broker:
            probe.index, probe.untracked = initial_git, initial_untracked
            probe.head, probe.common = snapshot.head, snapshot.git_common_dir
            probe.branch = snapshot.branch
            probe.configs = broker.configs
            probe.ignored_discovery = initial_discovery
            probe.discovery_patterns = discovery_patterns
    result.evidence.sort(key=lambda e: e.evidence_id)
    for capability in ("git_state", "local_content"):
        result.coverage.append(
            Coverage(
                source_id="local-git",
                capability=capability,
                status="not_inspected"
                if capability == "git_state" and not git_enabled
                else "partial"
                if reasons or changed
                else "complete",
                reasons=["git_identity_untrusted_not_collected"]
                if capability == "git_state" and not git_enabled
                else snapshot.reasons,
                result_count=len(snapshot.entries)
                if capability == "git_state"
                else len(result.evidence),
                scope=f"{scope}: declared bounded checkout scope",
            )
        )
    return snapshot, result
