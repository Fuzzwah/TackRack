"""Inert mixed-project descriptions; none of the recorded commands are executed."""

import builtins
import socket
import subprocess

import pytest

from tackrack.domain.models import Attachment, EvidenceRecord, Report, Snapshot, canonical_digest
from tackrack.plugins.detectors import BoundaryDetector, reference_targets
from tackrack.plugins.inventory import build_inventory


def evidence(
    path: str, text: str, revision: str = "working", scope: str = "project", **kwargs
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=canonical_digest([scope, path, revision, text]),
        source_id="local-git",
        kind="file",
        scope=scope,
        revision=revision,
        path=path,
        path_bytes=path.encode().hex(),
        digest=canonical_digest(text),
        collected_at="2026-10-14T00:00:00Z",
        excerpt=text,
        byte_end=len(text.encode()),
        payload={"exact_utf8_excerpt": True, "mode": "100644", "stage": 0},
        **kwargs,
    )


def report_for(records: list[EvidenceRecord]) -> Report:
    components, relationships, findings = BoundaryDetector().detect(records)
    # Mirror application resolution using only the supplied, authorised evidence.
    paths = {f"{record.scope}:{record.path}" for record in records}
    for relation in relationships:
        if relation.target in paths:
            relation.unresolved = False
    return Report(
        command="scan",
        operation_id="inventory-unit",
        project=Snapshot(root="/not-accessed/project"),
        attachment=Attachment(slot="/not-accessed/project/.agents", slot_role="embedded"),
        evidence=records,
        components=components,
        relationships=relationships,
        findings=findings,
    )


def test_mixed_project_inventory_aggregates_revisions_and_retains_resources() -> None:
    sources = {
        ".omp/commands/opsx-sync.md": "Use openspec status; --store <id> selects context. Read openspec/specs/.",
        ".omp/skills/openspec-sync/SKILL.md": "OpenSpec specification workflow.",
        "AGENTS.md": "# Architecture\nProject gameplay rules stay here.\n# Workflow\nUse /shipit after reviewed plan.\nRead docs/testing.md and scripts/check.js.",
        ".agents/skills/shipit/SKILL.md": "# Ship\nFollow [instructions](../../../AGENTS.md) and [checks](../../../docs/testing.md).",
        "docs/testing.md": "Project checks and physical native acceptance.",
        "scripts/check.js": "export const check = () => true;",
        "src/runtime.js": 'const prompt = "Use OpenSpec, OMP, AGENTS.md and /shipit";',
    }
    records = [
        evidence(path, text, revision)
        for path, text in sources.items()
        for revision in ("head", "index", "working")
    ]
    report = report_for(records)
    tools, extraction = build_inventory(report)
    by_name = {tool.name: tool for tool in tools}
    assert set(by_name) == {
        "OMP",
        "OpenSpec",
        "Generic agent instructions",
        "Shared agent skills",
        "Shipping workflow",
    }
    assert len(tools) == len(by_name)
    assert by_name["OMP"].revisions == ["head", "index", "working"]
    assert len(by_name["OMP"].paths) == 2
    assert len(by_name["OMP"].evidence_ids) == 6
    assert all(tool.configured == "yes" and tool.observed == "unknown" for tool in tools)
    items = {item.path: item for item in extraction.items}
    assert items["AGENTS.md"].disposition == "split"
    assert items[".omp/commands/opsx-sync.md"].disposition == "move"
    assert items[".agents/skills/shipit/SKILL.md"].disposition == "move"
    for path in ("docs/testing.md", "scripts/check.js", "src/runtime.js"):
        assert items[path].disposition == "keep"
    assert "project:AGENTS.md" in items[".agents/skills/shipit/SKILL.md"].references
    assert extraction.status == "blocked"
    assert sum("selected store" in blocker for blocker in extraction.blockers) == 1
    assert not any(
        relation.target == "project:openspec/specs/" for relation in report.relationships
    )
    assert any(relation.target == "external:openspec/specs/" for relation in report.relationships)


@pytest.mark.parametrize(("revision", "state"), [("head", "historical"), ("index", "staged")])
def test_nonworking_sources_are_not_configured(revision: str, state: str) -> None:
    tools, extraction = build_inventory(report_for([evidence(".omp/config.json", "{}", revision)]))
    assert tools[0].name == "OMP"
    assert tools[0].state == state
    assert tools[0].configured == "unknown"
    assert extraction.items[0].disposition == "review"


def test_historical_tool_does_not_override_current_family() -> None:
    tools, _ = build_inventory(
        report_for(
            [
                evidence(".omp/config.json", "{}", "head"),
                evidence(".codex/config.toml", "model = 'test'"),
            ]
        )
    )
    tools_by_name = {tool.name: tool for tool in tools}
    assert tools_by_name["OMP"].state == "historical"
    assert tools_by_name["Codex"].state == "configured"


def test_disabled_and_manual_profiles_are_intent_not_active_harnesses() -> None:
    records = [
        evidence(
            "profiles/omp/profile.toml", 'adapter = "omp"\nenabled = false\n', scope="workbench"
        ),
        evidence("profiles/omp/context.md", "OMP intended context", scope="workbench"),
        evidence(
            "profiles/manual/profile.toml",
            'adapter = "manual"\nenabled = true\nrender_strategy = "manual"\n',
            scope="workbench",
        ),
    ]
    tools, extraction = build_inventory(report_for(records))
    assert {tool.name: tool.state for tool in tools} == {"manual": "manual", "omp": "disabled"}
    assert all(tool.kind == "intended_profile" and tool.configured == "no" for tool in tools)
    assert all(item.disposition == "review" for item in extraction.items)


def test_independent_companion_ownership_and_relative_project_links() -> None:
    report = report_for(
        [
            evidence("project.toml", 'name = "example"', scope="workbench"),
            evidence("policy.toml", "schema_version = 1", scope="workbench"),
            evidence(
                "skills/shipit/SKILL.md", "Follow [root](../../../AGENTS.md).", scope="workbench"
            ),
            evidence("AGENTS.md", "Repository instructions"),
        ]
    )
    tools, extraction = build_inventory(report)
    components = {component.path: component for component in report.components}
    assert components["project.toml"].ownership == "project_binding"
    assert components["policy.toml"].ownership == "workflow_policy"
    assert components["skills/shipit/SKILL.md"].ownership == "harness_implementation"
    assert any(
        relation.target == "project:AGENTS.md" and not relation.unresolved
        for relation in report.relationships
    )
    assert {tool.name for tool in tools} == {
        "Generic agent instructions",
        "Shared agent skills",
        "Shipping workflow",
    }
    assert (
        next(item for item in extraction.items if item.path == "policy.toml").disposition == "keep"
    )
    assert (
        next(item for item in extraction.items if item.path == "skills/shipit/SKILL.md").disposition
        == "keep"
    )


def test_runtime_templates_and_fixture_strings_do_not_create_tools() -> None:
    records = [
        evidence(path, "OMP OpenSpec AGENTS.md /shipit .omp/config.json")
        for path in (
            "src/runtime.py",
            "templates/AGENTS.md.template",
            "tests/fixtures/omp-config.fixture.json",
            "docs/agent-example.md",
            "AGENTS.md.template",
        )
    ]
    tools, extraction = build_inventory(report_for(records))
    assert tools == []
    assert extraction.status == "no_candidates"
    assert all(item.disposition == "keep" for item in extraction.items)


@pytest.mark.parametrize("flag", ["redacted", "truncated"])
def test_incomplete_native_source_is_review_only(flag: str) -> None:
    record = evidence(".omp/commands/review.md", "Agent workflow", **{flag: True})
    _, extraction = build_inventory(report_for([record]))
    assert extraction.items[0].disposition == "review"
    assert extraction.items[0].blockers


def test_native_generated_workflow_examples_do_not_make_false_mixed_ownership() -> None:
    report = report_for(
        [
            evidence(
                ".omp/skills/openspec-explore/SKILL.md",
                "OpenSpec agent workflow.\nExample: inspect application architecture and domain model.",
            )
        ]
    )
    assert report.components[0].ownership == "harness_implementation"
    assert report.components[0].disposition == "move"


def test_exact_spans_preserve_byte_offsets_and_provenance() -> None:
    record = evidence(
        "AGENTS.md",
        "# Architecture é\nApplication uses domain model.\n# Workflow\nUse /shipit after reviewed plan.\n",
    )
    record.byte_start = 17
    report = report_for([record])
    component = report.components[0]
    assert component.evidence_ids == [record.evidence_id]
    assert len(component.ownership_spans) == 2
    raw = record.excerpt.encode()
    for span in component.ownership_spans:
        start, end = span["byte_start"] - 17, span["byte_end"] - 17
        assert raw[start:end].decode()
    record.payload["exact_utf8_excerpt"] = False
    assert not report_for([record]).components[0].ownership_spans


def test_relative_markdown_external_roots_and_store_fallbacks_are_lexical() -> None:
    record = evidence(
        ".agents/skills/shipit/SKILL.md",
        "[instructions](../../../AGENTS.md#rules) [check](../../../scripts/check.js) [external](../../../../outside.md) [url](https://example.test/docs/no.md) [root](/outside/spec.md)",
    )
    assert reference_targets(record) == [
        "external:../outside.md",
        "external:/outside/spec.md",
        "project:AGENTS.md",
        "project:scripts/check.js",
    ]
    optional = evidence(
        ".omp/commands/spec.md", "OpenSpec uses --store <id>, otherwise openspec/specs/ is local."
    )
    assert reference_targets(optional) == ["external:openspec/specs/"]
    local = evidence("AGENTS.md", "Read openspec/specs/ and docs/testing.md")
    assert reference_targets(local) == ["project:docs/testing.md", "project:openspec/specs/"]


def test_pure_detection_and_inventory_never_access_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    records = [
        evidence(
            ".omp/commands/spec.md",
            "OpenSpec: use openspec context --store remote. Read openspec/specs/.",
        )
    ]

    def forbidden(*args, **kwargs):
        raise AssertionError("Detection must not access target files, launch processes, or connect")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    tools, extraction = build_inventory(report_for(records))
    assert {tool.name for tool in tools} == {"OMP", "OpenSpec"}
    assert extraction.status == "blocked"


def test_store_alternative_declarations_apply_across_same_revision_inputs() -> None:
    report = report_for(
        [
            evidence(
                ".omp/skills/openspec/SKILL.md",
                "OpenSpec permits --store <id> and openspec context.",
            ),
            evidence("AGENTS.md", "Workflow: read openspec/specs/ before completing."),
        ]
    )
    assert any(relation.target == "external:openspec/specs/" for relation in report.relationships)
    assert not any(
        relation.target == "project:openspec/specs/" for relation in report.relationships
    )
    historical = report_for(
        [
            evidence(".omp/skills/openspec/SKILL.md", "OpenSpec permits --store <id>.", "head"),
            evidence("AGENTS.md", "Workflow: read openspec/specs/ before completing."),
        ]
    )
    assert any(
        relation.target == "project:openspec/specs/" for relation in historical.relationships
    )


def test_hosted_action_revisions_are_one_declared_tool() -> None:
    text = "jobs:\n  review:\n    steps:\n      - uses: openai/codex-action@v1\n"
    tools, extraction = build_inventory(
        report_for(
            [
                evidence(".github/workflows/review.yml", text, revision)
                for revision in ("head", "index", "working")
            ]
        )
    )
    assert len(tools) == 1
    assert tools[0].name == "openai/codex-action"
    assert tools[0].location == "hosted"
    assert tools[0].configured == "yes"
    assert tools[0].observed == "unknown"
    assert tools[0].revisions == ["head", "index", "working"]
    assert extraction.items[0].disposition == "review"


def test_hosted_definition_and_observation_share_one_inventory_record() -> None:
    records = []
    for kind in ("workflow_definition", "workflow_run"):
        item = evidence(kind, kind, scope="hosting")
        item.kind = "hosting_observation"
        item.path = None
        item.payload = {"observation": {"kind": kind, "name": "AI code review"}}
        records.append(item)
    tools, _ = build_inventory(report_for(records))
    assert len(tools) == 1
    assert tools[0].configured == "yes"
    assert tools[0].observed == "yes"
    assert len(tools[0].evidence_ids) == 2


def test_truncated_mixed_instructions_do_not_offer_exact_split_spans() -> None:
    report = report_for(
        [
            evidence(
                "AGENTS.md",
                "# Architecture\nProject runtime rules.\n# Workflow\nUse /shipit after reviewed plan.",
                truncated=True,
            )
        ]
    )
    assert report.components[0].disposition == "review"
    assert report.components[0].ownership_spans == []
    _, extraction = build_inventory(report)
    assert extraction.items[0].disposition == "review"


def test_manifest_default_profile_is_only_a_declaration() -> None:
    tools, _ = build_inventory(
        report_for(
            [
                evidence("project.toml", 'default_profile = "omp"', scope="workbench"),
            ]
        )
    )
    assert len(tools) == 1
    assert tools[0].kind == "intended_profile"
    assert tools[0].state == "declared"
    assert tools[0].configured == "unknown"


def test_large_product_knowledge_and_runtime_assets_are_not_extraction_candidates() -> None:
    records = [
        evidence("docs/testing.md", "Product-owned checks", truncated=True),
        evidence("openspec/specs/domain/spec.md", "Product requirement", truncated=True),
        evidence("src/runtime.js", "Runtime implementation", truncated=True),
    ]
    _, extraction = build_inventory(report_for(records))
    assert all(item.disposition == "keep" and not item.blockers for item in extraction.items)
    assert extraction.status == "no_candidates"


def test_live_nested_test_instructions_are_not_hidden_by_a_fixture_directory_label() -> None:
    report = report_for(
        [evidence("tests/AGENTS.md", "Agent workflow: review tests before completion.")]
    )
    tools, _ = build_inventory(report)
    assert any(tool.name == "Generic agent instructions" for tool in tools)
    assert any(finding.rule_id == "TR-A019" for finding in report.findings)


def test_embedded_workflow_policy_is_a_companion_candidate_not_product_knowledge() -> None:
    _, extraction = build_inventory(
        report_for(
            [
                evidence(".agents/policy/workflow.toml", "require_review = true"),
                evidence(".agents/project.toml", 'name = "project"'),
            ]
        )
    )
    assert {item.ownership for item in extraction.items} == {"workflow_policy", "project_binding"}
    assert all(item.disposition == "move" for item in extraction.items)
