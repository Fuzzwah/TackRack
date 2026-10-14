"""Manual adapter: no process, exports, or model invocation."""

from __future__ import annotations

import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class Resource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    root: str
    path: str
    required: bool = True


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    argv: list[str]
    cwd: str
    required: bool = True


class Boundary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attachment_policy: str = "contained"
    tracked_bridges: str = "deny"
    allow_product_templates_and_inert_fixtures: bool = True


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int
    project_id: UUID
    companion_id: UUID
    name: str
    default_profile: str = "manual"
    workflow_policy: str
    shipping_contract: str
    boundary: Boundary = Field(default_factory=Boundary)
    resources: list[Resource] = Field(default_factory=list)
    checks: list[Check] = Field(default_factory=list)


class ManualRequirements(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_resource_references: Literal["required"] = "required"
    external_workflow_state: Literal["required"] = "required"
    model_invocation: Literal["not_required"] = "not_required"


class ManualProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    name: Literal["manual"] = "manual"
    adapter: Literal["manual"]
    enabled: Literal[True]
    render_strategy: Literal["manual"]
    context_file: str
    requirements: ManualRequirements = Field(default_factory=ManualRequirements)


def safe_resource(root: Path, relative: str) -> Path:
    path = PurePosixPath(relative)
    if not relative or path.is_absolute() or ".." in path.parts or "\\" in relative:
        raise ValueError("unsafe_resource_path")
    candidate = root / relative
    node = root
    for part in path.parts:
        node /= part
        if node.is_symlink():
            raise ValueError("resource_symlink_not_followed")
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError("resource_outside_root")
    return candidate


def read_toml(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("manifest_missing_unsafe_or_oversized")
    return tomllib.loads(path.read_text("utf-8"))


def read_manifest(workbench: Path) -> Manifest:
    manifest = Manifest.model_validate(read_toml(workbench / "project.toml"))
    if manifest.schema_version != 1 or manifest.project_id == manifest.companion_id:
        raise ValueError("invalid_manifest_identity_or_version")
    if (
        manifest.boundary.attachment_policy != "contained"
        or manifest.boundary.tracked_bridges != "deny"
    ):
        # M1 does not implement approved exceptions; it cannot trust a self-waiver.
        raise ValueError("boundary_exception_not_supported_in_foundation")
    for relative in (manifest.workflow_policy, manifest.shipping_contract):
        safe_resource(workbench, relative)
    for resource in manifest.resources:
        if (
            resource.root != "project"
            or resource.path == ".agents"
            or resource.path.startswith(".agents/")
        ):
            raise ValueError("invalid_project_resource_namespace")
        safe_resource(Path("/validation-root"), resource.path)
    for check in manifest.checks:
        if check.cwd not in {"${project}", "${workbench}"} or not check.argv:
            raise ValueError("invalid_check_binding")
        for arg in check.argv:
            if "${" in arg and arg not in {"${project}", "${workbench}", "${run}"}:
                raise ValueError("unknown_root_substitution")
    return manifest


class ManualAdapter:
    plugin_id = "manual"
    plugin_version = "0.1.0"

    def assess(self, project: Path, workbench: Path, profile: str = "manual") -> dict[str, Any]:
        if profile != "manual":
            return {
                "status": "unverified",
                "adapter": profile,
                "reason": "Real harness adapter/version contract is not implemented.",
            }
        manifest = read_manifest(workbench)
        config = ManualProfile.model_validate(
            read_toml(safe_resource(workbench, "profiles/manual/profile.toml"))
        )
        context = safe_resource(workbench, "profiles/manual/" + config.context_file)
        missing = [
            r.id
            for r in manifest.resources
            if r.required and not safe_resource(project, r.path).is_file()
        ]
        if not context.is_file():
            missing.append("manual_context")
        return {
            "status": "compatible" if not missing else "unsupported",
            "adapter": "manual",
            "missing_resources": missing,
            "requirements": {
                "project_resource_references": "external" if not missing else "unsupported",
                "external_workflow_state": "external",
                "model_invocation": "not_required",
            },
            "launch": "none",
            "rendered_outputs": [],
            "limitations": [
                "Context must be supplied explicitly; no automatic discovery or lifecycle enforcement."
            ],
        }

    def render(self) -> dict[str, Any]:
        return {"strategy": "manual", "outputs": [], "process": None}
