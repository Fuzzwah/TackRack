"""Terminal-first public surface: only implemented operations are registered."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Annotated, Any

import typer

from tackrack.application.inspection import inspect, inspected_roots
from tackrack.application.inspection import register as register_pair
from tackrack.cli.render import markdown
from tackrack.infrastructure.git import GitError, discover_root
from tackrack.infrastructure.state import StateError, Store, external_path, peek_binding

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Evidence-based AI development boundary inspection. Scan/audit never execute or repair the target.",
    pretty_exceptions_enable=False,
)
plugins_app = typer.Typer(
    no_args_is_help=True, help="Installed trusted plugin metadata; no arbitrary plugin imports."
)
app.add_typer(plugins_app, name="plugins")


def emit(value: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        typer.echo(json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True))
    else:
        typer.echo(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2))


def failure(command: str, exc: Exception, fmt: str) -> None:
    reason = exc.reason if isinstance(exc, GitError) else str(exc).split("\n")[0][:150]
    emit(
        {
            "schema_version": 1,
            "command": command,
            "operation_id": str(uuid.uuid4()),
            "status": "blocked",
            "coverage": [],
            "artifacts": [],
            "findings": [],
            "errors": [
                {
                    "reason": reason,
                    "next_step": "Review the named scope/root; authorise a separate operation if needed.",
                }
            ],
            "exit_code": 2,
        },
        fmt,
    )
    raise typer.Exit(2)


def resolve_subject(subject: str) -> tuple[Path, Store]:
    candidate = Path(subject).expanduser()
    if candidate.exists():
        root = discover_root(candidate)
        binding = peek_binding(inspected_roots(root), project=root)
        if binding is None:
            binding = peek_binding(inspected_roots(root), workbench=root)
            if binding:
                root = discover_root(Path(binding["project_path"]))
        workbench = Path(binding["workbench_path"]) if binding else root / ".agents"
        return root, Store(inspected_roots(root, workbench))
    try:
        forbidden = inspected_roots(discover_root(Path.cwd()))
    except GitError:
        forbidden = []
    binding = peek_binding(forbidden, name=subject)
    if binding is None:
        raise StateError("unknown_project_binding_or_missing_path")
    root = discover_root(Path(binding["project_path"]))
    workbench = Path(binding["workbench_path"])
    return root, Store(inspected_roots(root, workbench))


def run_inspection(
    command: str,
    subject: str,
    offline: bool,
    attachment: str,
    fmt: str,
    out: Path | None,
    sources: str,
    remote: str | None,
    allow_network: bool,
    profile: str | None,
    include_ignored: bool,
) -> None:
    store: Store | None = None
    try:
        if fmt not in {"json", "text", "markdown"} or attachment not in {"auto", "none", "full"}:
            raise ValueError("invalid_format_or_attachment_mode")
        if sources != "auto" and (
            not set(sources.split(",")) <= {"local-git", "github"}
            or "local-git" not in sources.split(",")
        ):
            raise ValueError("sources_require_local_git_and_optional_github")
        root, store = resolve_subject(subject)
        binding = store.by_project(root)
        workbench = Path(binding["workbench_path"]) if binding else root / ".agents"
        if out:
            out = external_path(out, inspected_roots(root, workbench))
            if out.exists() or out.is_symlink():
                raise ValueError("report_destination_already_exists")
        report = inspect(
            root,
            store,
            command=command,
            attachment_mode=attachment,
            offline=offline,
            sources=sources,
            remote=remote,
            allow_network=allow_network,
            profile=profile,
            include_ignored=include_ignored,
        )
        render_needed = fmt != "json" or (out is not None and out.suffix != ".json")
        text = (
            markdown(report, display_timezone=binding.get("timezone", "UTC") if binding else "UTC")
            if render_needed
            else ""
        )
        if out:
            out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            payload = (
                json.dumps(
                    report.model_dump(mode="json"), ensure_ascii=True, sort_keys=True, indent=2
                )
                if out.suffix == ".json"
                else text
            )
            # Refuse to clobber user outputs; explicit external output only.
            out = external_path(out, inspected_roots(root, workbench))
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload + ("\n" if not payload.endswith("\n") else ""))
            report.artifacts.append(str(out))
        blob = store.save_report(report.model_dump(mode="json"))
        report.artifacts.append(blob)
        if fmt == "json":
            emit(report.model_dump(mode="json"), fmt)
        else:
            typer.echo(text)
        code = report.exit_code
    except (GitError, StateError, ValueError, OSError) as exc:
        failure(command, exc, fmt)
    finally:
        if store:
            store.close()
    raise typer.Exit(code)


Subject = Annotated[str, typer.Argument(help="Checkout path or registered project name.")]
AttachmentOption = Annotated[
    str, typer.Option(help="Companion evidence scope: auto, none, full (not activation).")
]
FormatOption = Annotated[
    str, typer.Option("--format", help="text, markdown, json; JSON stdout is one envelope.")
]
OutOption = Annotated[
    Path | None,
    typer.Option(
        help="New output outside inspected roots (.json selects JSON, otherwise Markdown)."
    ),
]


@app.command()
def scan(
    subject: Subject,
    offline: bool = False,
    attachment: AttachmentOption = "auto",
    output_format: FormatOption = "text",
    out: OutOption = None,
    sources: str = "auto",
    remote: str | None = None,
    allow_network: bool = False,
    profile: str | None = None,
    include_ignored: bool = False,
) -> None:
    """Discover bounded local and explicitly authorised hosting evidence, without target writes."""
    run_inspection(
        "scan",
        subject,
        offline,
        attachment,
        output_format,
        out,
        sources,
        remote,
        allow_network,
        profile,
        include_ignored,
    )


@app.command()
def audit(
    subject: Subject,
    offline: bool = False,
    attachment: AttachmentOption = "auto",
    output_format: FormatOption = "text",
    out: OutOption = None,
    sources: str = "auto",
    remote: str | None = None,
    allow_network: bool = False,
    profile: str | None = None,
    include_ignored: bool = False,
) -> None:
    """Assess a fresh snapshot; never execute checks/harnesses, fix files, or alter remote settings."""
    run_inspection(
        "audit",
        subject,
        offline,
        attachment,
        output_format,
        out,
        sources,
        remote,
        allow_network,
        profile,
        include_ignored,
    )


@app.command()
def register(
    name: Annotated[str, typer.Argument()],
    project: Path = typer.Option(...),
    workbench: Path = typer.Option(...),
    output_format: FormatOption = "text",
    trust_policy: bool = False,
    remote: str | None = None,
) -> None:
    """Bind existing independent roots only. --trust-policy explicitly trusts reviewed manifest data."""
    store: Store | None = None
    try:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name) or output_format not in {"text", "json"}:
            raise ValueError("invalid_binding_name_or_format")
        root = discover_root(project)
        store = Store(inspected_roots(root, workbench))
        binding = register_pair(
            name, root, workbench, store, trust_policy=trust_policy, remote_name=remote
        )
        emit(
            {
                "schema_version": 1,
                "command": "register",
                "operation_id": str(uuid.uuid4()),
                "status": "completed",
                "binding": binding,
                "coverage": [],
                "findings": [],
                "errors": [],
                "artifacts": [str(store.database)],
                "exit_code": 0,
            },
            output_format,
        )
    except (GitError, StateError, ValueError, OSError) as exc:
        failure("register", exc, output_format)
    finally:
        if store:
            store.close()


@plugins_app.command("list")
def plugins_list(output_format: FormatOption = "text") -> None:
    """Inspect built-ins and installed entry-point metadata without importing third-party code."""
    from importlib.metadata import distributions

    if output_format not in {"text", "json"}:
        failure("plugins list", ValueError("invalid_format"), output_format)
    builtin = [
        {
            "plugin_id": "local-git",
            "family": "source",
            "version": "0.1.0",
            "api_version": 1,
            "trust": "builtin",
            "capabilities": ["git_state", "local_content", "attachment_boundary"],
        },
        {
            "plugin_id": "github",
            "family": "source",
            "version": "0.1.0",
            "api_version": 1,
            "trust": "builtin",
            "capabilities": [
                "github.repository",
                "github.actions_runs",
                "github.rulesets",
                "github.workflow_definitions",
            ],
        },
        {
            "plugin_id": "local-boundary",
            "family": "detector",
            "version": "0.1.0",
            "api_version": 1,
            "trust": "builtin",
            "capabilities": ["static_ownership", "discovery_surfaces"],
        },
        {
            "plugin_id": "manual",
            "family": "adapter",
            "version": "0.1.0",
            "api_version": 1,
            "trust": "builtin",
            "capabilities": ["static_resource_assessment", "no_process"],
        },
    ]
    untrusted: list[dict[str, str]] = []
    for dist in distributions():
        for entry in dist.entry_points:
            if (
                entry.group
                in {"tackrack.sources.v1", "tackrack.detectors.v1", "tackrack.adapters.v1"}
                and dist.metadata["Name"] != "tackrack"
            ):
                untrusted.append(
                    {
                        "distribution": dist.metadata["Name"],
                        "version": dist.version,
                        "entry_point": entry.name,
                        "group": entry.group,
                        "trust": "untrusted_not_imported",
                    }
                )
    emit(
        {
            "schema_version": 1,
            "command": "plugins list",
            "operation_id": str(uuid.uuid4()),
            "status": "completed",
            "plugins": sorted(builtin, key=lambda p: str(p["plugin_id"])),
            "untrusted_installed": sorted(
                untrusted, key=lambda p: (p["distribution"], p["entry_point"])
            ),
            "coverage": [],
            "artifacts": [],
            "findings": [],
            "errors": [],
            "exit_code": 0,
        },
        output_format,
    )
