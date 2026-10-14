"""Small private SQLite registry/receipt store. No approvals or mutable ledger exports."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from tackrack.domain.models import canonical_digest, utc_now


class StateError(Exception):
    pass


def external_path(path: Path, forbidden: list[Path]) -> Path:
    resolved = path.expanduser().resolve()
    for root in forbidden:
        root = root.resolve()
        if resolved == root or resolved.is_relative_to(root):
            raise StateError("output_or_state_inside_inspected_root")
    return resolved


def user_roots(forbidden: list[Path]) -> dict[str, Path]:
    home = Path.home()
    defaults = {
        "config": Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config"))) / "tackrack",
        "state": Path(os.environ.get("XDG_STATE_HOME", str(home / ".local/state"))) / "tackrack",
        "cache": Path(os.environ.get("XDG_CACHE_HOME", str(home / ".cache"))) / "tackrack",
    }
    roots: dict[str, Path] = {}
    for key, default in defaults.items():
        value = Path(os.environ.get(f"TACKRACK_{key.upper()}_DIR", str(default)))
        if not value.is_absolute():
            raise StateError("state_override_must_be_absolute")
        roots[key] = external_path(value, forbidden)
    if len(set(roots.values())) != 3:
        raise StateError("config_state_cache_roots_must_be_distinct")
    return roots


def peek_binding(
    forbidden: list[Path],
    *,
    name: str | None = None,
    project: Path | None = None,
    workbench: Path | None = None,
) -> dict[str, Any] | None:
    """Discover existing root declarations without creating state before root validation."""
    database = user_roots(forbidden)["state"] / "ledger.sqlite3"
    if not database.exists():
        return None
    if database.is_symlink():
        raise StateError("state_database_symlink")
    try:
        with sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True) as db:
            if name is not None:
                row = db.execute("SELECT record FROM bindings WHERE name=?", (name,)).fetchone()
                return json.loads(row[0]) if row else None
            for row in db.execute("SELECT record FROM bindings ORDER BY name"):
                record: dict[str, Any] = json.loads(row[0])
                if (
                    project is not None
                    and Path(record["project_path"]).resolve() == project.resolve()
                ):
                    return record
                if (
                    workbench is not None
                    and Path(record["workbench_path"]).resolve() == workbench.resolve()
                ):
                    return record
    except sqlite3.DatabaseError as exc:
        raise StateError("binding_registry_unavailable_or_invalid") from exc
    return None


class Store:
    def __init__(self, forbidden: list[Path]) -> None:
        self.forbidden = forbidden
        self.roots = user_roots(forbidden)
        state = self.roots["state"]
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        database = state / "ledger.sqlite3"
        if database.is_symlink():
            raise StateError("state_database_symlink")
        self.database = external_path(database, forbidden)
        if self.database.exists():
            try:
                with sqlite3.connect(
                    self.database.as_uri() + "?mode=ro&immutable=1", uri=True
                ) as existing:
                    versions = existing.execute("SELECT version FROM schema_version").fetchall()
                    if versions != [(1,)]:
                        raise StateError("unsupported_ledger_schema")
            except sqlite3.DatabaseError as exc:
                raise StateError("unrecognised_ledger_database") from exc
        self.db = sqlite3.connect(self.database, timeout=10)
        os.chmod(self.database, 0o600)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);
            INSERT OR IGNORE INTO schema_version VALUES (1);
            CREATE TABLE IF NOT EXISTS bindings (
                name TEXT PRIMARY KEY, record TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS identities (
                root TEXT PRIMARY KEY, project_id TEXT NOT NULL, checkout_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS blobs (
                digest TEXT PRIMARY KEY, path TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS operations (
                operation_id TEXT PRIMARY KEY, command TEXT NOT NULL,
                digest TEXT NOT NULL REFERENCES blobs(digest), created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS notes (
                note_id TEXT PRIMARY KEY, binding_name TEXT NOT NULL,
                actor TEXT NOT NULL CHECK(actor='agent'), payload TEXT NOT NULL,
                created_at TEXT NOT NULL);
        """)
        versions = self.db.execute("SELECT version FROM schema_version").fetchall()
        if versions != [(1,)]:
            self.db.close()
            raise StateError("unsupported_ledger_schema")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def binding(self, name: str) -> dict[str, Any] | None:
        row = self.db.execute("SELECT record FROM bindings WHERE name=?", (name,)).fetchone()
        return json.loads(row[0]) if row else None

    def by_project(self, root: Path) -> dict[str, Any] | None:
        for row in self.db.execute("SELECT record FROM bindings ORDER BY name"):
            record: dict[str, Any] = json.loads(row[0])
            if Path(record["project_path"]).resolve() == root.resolve():
                return record
        return None

    def identity(self, root: Path) -> tuple[str, str]:
        key = str(root.resolve())
        self.db.execute(
            "INSERT OR IGNORE INTO identities VALUES (?,?,?)",
            (key, str(uuid.uuid4()), str(uuid.uuid4())),
        )
        self.db.commit()
        row = self.db.execute(
            "SELECT project_id, checkout_id FROM identities WHERE root=?", (key,)
        ).fetchone()
        assert row is not None
        return str(row[0]), str(row[1])

    def register(self, name: str, record: dict[str, Any]) -> dict[str, Any]:
        existing = self.binding(name)
        if existing is not None:
            if existing != record:
                raise StateError("binding_name_already_exists")
            return existing
        if self.by_project(Path(record["project_path"])) is not None:
            raise StateError("physical_checkout_already_registered")
        self.db.execute(
            "INSERT INTO bindings VALUES (?,?,?)",
            (name, json.dumps(record, sort_keys=True), utc_now()),
        )
        self.db.commit()
        return record

    def save_report(self, report: dict[str, Any]) -> str:
        digest = canonical_digest(report)
        folder = external_path(self.roots["state"] / "blobs" / digest[:2], self.forbidden)
        if not folder.is_relative_to(self.roots["state"]):
            raise StateError("blob_path_escapes_state_root")
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        blob = folder / (digest + ".json")
        data = json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
        if not blob.exists():
            fd = os.open(blob, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            directory_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        elif blob.is_symlink() or blob.read_bytes() != data:
            raise StateError("blob_conflict")
        self.db.execute("INSERT OR IGNORE INTO blobs VALUES (?,?)", (digest, str(blob)))
        self.db.execute(
            "INSERT INTO operations VALUES (?,?,?,?)",
            (report["operation_id"], report["command"], digest, utc_now()),
        )
        self.db.commit()
        return str(blob)

    def import_agent_note(self, binding_name: str, source_path: str, text: str) -> None:
        # Historical provenance only. Never interpreted as grants or approvals.
        payload = {
            "schema_version": 1,
            "source_path": source_path,
            "source_kind": "temporary_bootstrap_note",
            "text": text,
        }
        self.db.execute(
            "INSERT INTO notes VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), binding_name, "agent", json.dumps(payload), utc_now()),
        )
        self.db.commit()
