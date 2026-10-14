# TackRack

TackRack is a local-first tool for discovering and explaining the **AI tooling used to develop a software project**, including **local coding harnesses** and **remote/hosted AI integrations**. Python 3.12+.

## Purpose

The primary question is: **What AI development tooling is present, how is it connected, and what evidence shows it is configured or being used?**

- **Local tooling:** project and companion instruction files, harness configuration, and declared profiles. A configuration file does not prove that its harness is installed, enabled, or running.
- **Remote/hosted tooling:** AI-assisted CI, code-review automation, and other development-agent integrations evidenced by repository workflows and approved hosting APIs. GitHub is the first supported hosting source; this does not imply visibility into every cloud agent or service.
- **Evidence and coverage:** distinguish declared configuration, references, observed runs, and technical enforcement. Uninspected, inaccessible, or unsupported inputs remain explicit—not “no tools found.”

Ownership and containment checks support this inventory: they help distinguish development-time AI from AI shipped as part of the product, and identify workflow/source coupling. TackRack is **not merely a `.agents/` hygiene checker**, and it does not infer whether source code was written by AI.

The longer-term workbench adds reviewed, reversible extraction and interchangeable harness profiles. Those operations are not part of the current read-only foundation.

## Run

```fish
uv sync --locked
uv run --locked tackrack --help
uv run --locked tackrack scan . --offline --format json
uv run --locked tackrack audit . --offline
uv run --locked tackrack plugins list

# Optional: explicitly request read-only GitHub metadata for the product remote.
uv run --locked tackrack scan . --sources local-git,github --remote origin --allow-network
```

`scan` asks **what AI development machinery can be found in the requested scope** and produces an extraction-review inventory. It does not require the project to be separated already: root `AGENTS.md`, tracked `.omp` integration, and a product-owned `.agents/skills` directory are valid inputs. Separation policy is `not_assessed`; a completed discovery scan does not fail just because those inputs are embedded. `audit` separately evaluates the proposed ownership/containment boundary. Neither executes project/harness code, fixes files, or changes Git/hosting settings. Both save private reports externally. `--offline` leaves remote evidence unassessed; static results never prove universal isolation or product independence.

## Current implementation

Implemented commands: `scan`, `audit`, `register`, and `plugins list`. The foundation includes local Git HEAD/index/working snapshots, bounded project/companion discovery, evidence/findings/relationships, manual-profile static assessment, local registration, plugin metadata, and restricted GitHub identity, workflow-definition references, workflow-run summaries, and visible ruleset reads.

The inventory names evidenced tooling and workflow families (including OMP, OpenSpec, generic agent instructions, shared shipping skills, intended profiles, and known hosted-agent callers), with paths and HEAD/index/working revisions retained separately. It distinguishes configured sources, disabled/intended profiles, historical declarations, and observed hosting metadata—not installed binaries or enforced gates. Extraction review distinguishes harness candidates, mixed instructions, retained project resources, and blockers. Detection remains catalogue-scoped; ambient configuration, PR interactions, and installed-integration policy are not assessed by default or are unsupported.

No AI account or companion is required for local scanning. Hosting reads require explicit `--allow-network`; `--offline` takes precedence. Real harness launch, extraction, attach/switch/detach, approval gates, and shipping are **not implemented**.

### Scanning before extraction

A normal project may own both product code and AI-development machinery. TackRack preserves that existing layout during discovery. An ordinary `.agents` directory is labelled **embedded product source**, not automatically adopted as an independent companion; its tracked authored skills/configuration are inspected in the product namespace. A valid independent companion remains a separate scope.

The review inventory can propose moving harness-only native payloads, splitting mixed instructions, and keeping architecture, tests, build/CI capabilities, runtime AI, and OpenSpec requirements/history in the product. Truncated or sensitive inputs, unresolved references, external OpenSpec store selection, dirty affected sources, and an occupied/tracked `.agents` target require review. These are **not executable migration operations**: no files are moved, untracked, overwritten, or deleted.

## Product and AI workbench ownership

The product builds and runs without a companion. An optional, independently versioned `.agents/` repository holds project-specific AI-development policy and profiles; it is ignored by product Git, not a submodule or product dependency. Durable operational state stays outside both repositories. Git exclusion is an ownership boundary, not secrecy or a security sandbox.

See [CLI](docs/cli.md), [contributing](docs/contributing.md), [design](docs/design.md), [architecture](docs/architecture.md), and [security](docs/security.md). No licence or package-publication ownership is assumed. Nothing is committed or published by bootstrap.
