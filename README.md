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

`scan` asks **what AI development machinery can be found in the requested scope**. `audit` evaluates the collected evidence against ownership, containment, and supported configuration rules. Neither executes project/harness code, fixes files, or changes Git/hosting settings. Both save private reports to external state. `--offline` prohibits network access, so it cannot establish the absence of remote AI tooling. A policy pass applies only to the assessed rules and scope—not universal isolation or verified product independence.

## Current implementation

Implemented commands: `scan`, `audit`, `register`, and `plugins list`. The foundation includes local Git HEAD/index/working snapshots, bounded project/companion discovery, evidence/findings/relationships, manual-profile static assessment, local registration, plugin metadata, and restricted GitHub identity, workflow-definition references, workflow-run summaries, and visible ruleset reads.

**The current inventory is still primarily file/configuration evidence, not a complete tool-by-tool harness assessment.** Detection is catalogue-scoped; runtime activity and enforcement remain unknown unless supported by collected evidence. Ambient/user-level configuration is not inspected by default. Pull-request interactions and installed-integration policy are currently unsupported.

No AI account or companion is required for local scanning. Hosting reads require explicit `--allow-network`; `--offline` takes precedence. Real harness launch, extraction, attach/switch/detach, approval gates, and shipping are **not implemented**.

## Product and AI workbench ownership

The product builds and runs without a companion. An optional, independently versioned `.agents/` repository holds project-specific AI-development policy and profiles; it is ignored by product Git, not a submodule or product dependency. Durable operational state stays outside both repositories. Git exclusion is an ownership boundary, not secrecy or a security sandbox.

See [CLI](docs/cli.md), [contributing](docs/contributing.md), [design](docs/design.md), [architecture](docs/architecture.md), and [security](docs/security.md). No licence or package-publication ownership is assumed. Nothing is committed or published by bootstrap.
