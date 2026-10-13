# TackRack design — revision 0.2

The supplied **System Design and Agent Bootstrap Specification**, dated 13 October 2026, is the authoritative bootstrap request. This maintained design records its architecture, ownership contracts, initial implementation and deferred milestones; it does not claim future features exist.

## Product intent

Understand how AI is used to develop a project; separate development machinery without losing project knowledge; support interchangeable harnesses without rebuilding workflow or contaminating product source. Do not infer AI authorship from source text. No mandatory AI account, hosted service, model routing, universal prompt language, or security sandbox in the initial product.

## Ownership

Product source, tests, requirements, docs, ordinary CI, runtime AI, scanner/adapter implementations, shipped inert templates and fixtures remain product-owned. AI-development policy, prompts, skills, profiles and AI-only tools belong to an independent companion. Machine bindings, credentials, durable history, approvals, runs, backups and journals remain physically external to both repositories.

The default companion is exactly product-root `.agents`, with its own `.git` and common-directory identity. Product `.gitignore` contains root-anchored `/.agents` without a trailing slash. This rule does not untrack existing entries. Product HEAD/index leaks remain visible, including exact-path files, symlinks, gitlinks and descendants. The reserved root is not a blanket exemption for arbitrary nested `.agents` paths. It is an ownership boundary, not access control.

Product capabilities must build/test/package/run without the real attachment. Positive package inclusion, isolated fixture tests and a standalone standard-library boundary guard establish distinct Git, filesystem, dependency and artifact checks. Synthetic companions are materialised only in temporary test roots. Ordinary checks never depend on the real developer companion.

## Data and trust

Versioned Pydantic records represent snapshots, byte-safe manifests, evidence, per-capability coverage, components, typed relationships, findings and report envelopes. Git committed/index/working revisions remain distinct. Git object IDs remain opaque with declared object format; TackRack identities use SHA-256 over sorted-key, compact, UTF-8 canonical JSON with ASCII escapes, no nonfinite numbers. Callers sort nonsemantic collections. Collection timestamps and local display paths are excluded from content fingerprints; file modes, deletion state, link-target bytes and scope limits are included. Durable registry IDs are UUIDs.

Paths carry project/workbench namespaces. Companion updates do not alter product-content fingerprints, but do change the pair. Reports are complete only relative to scope. Coverage states: complete, partial, not_inspected, permission_denied, unsupported, unavailable, rate_limited, error. No access is not evidence of absence. Activity separately reports configured, referenced, observed and enforced; static discovery establishes no execution or enforcement.

Disposition: keep, move, split, regenerate, bridge, review. Review blocks automatic deletion. Mixed prose gets bounded deterministic exact-span proposals; dynamic consumers and unresolved references remain review blockers. Runtime AI and substantive OpenSpec/project specifications stay product-owned. No migration occurs in M1.

Repository content, comments, profiles and imported data are untrusted evidence. Only trusted installed code may execute. Three plugin families: sources collect bounded evidence, detectors interpret immutable records without process/network access, adapters render/assess/launch under core control. Entry-point metadata is inventoried before code import; M1 loads only built-ins, not third-party code. GitHub-specific types stay out of the domain layer.

## Boundaries and workflow

Local `attachment_policy=contained` and `tracked_bridges=deny` are independent default axes. Compatibility projections and approved hosted bridges require separate manifests/approvals; neither exception is implemented in M1. Canonical inactive profile definitions must remain inert; active exports are generation-owned and distinct. Manual context is supplied explicitly and creates no process or exports. OMP/Codex records are disabled/unverified until real version-specific contracts exist.

Target lifecycle: Inspect → Plan → Setup → Implement → Verify → Human Testing → Human Sign-off → Document → Cleanup → Ship. Proportionate ceremony; OpenSpec optional within Implement. Candidate/plan-bound human decisions and action grants are distinct. Documentation/cleanup changes invalidate affected gates. Shipping defaults dry-run; commit, push, PR, merge, deploy, publication and specification finalisation require separate authority. M1 records inspection/binding/history-note provenance only; no lifecycle/approval enforcement exists.

Extraction target: reviewed immutable operation DAG, exact preimages/postimages, stable clean affected state, independent roots, explicit grants, external durable backups/journals, disposable validation and conflict-aware reversal. Never broad reset/clean, recursive user-worktree deletion, arbitrary shell operations or implicit staging. Index removal requires a dedicated grant. Attachment switching is not replacement; detach parks the complete companion externally, preserving dirty/user content and Git metadata. No cross-repository atomicity claim. All are M2+.

## Initial scope and roadmap

- **M0:** independent companion, locked Python product tooling, manual context, normal CI, external bootstrap provenance, independent guard and artifact/absent-companion verification.
- **M1:** offline scan/audit/register/plugin inventory, paired snapshots, coverage, deterministic findings, Markdown/JSON, real bounded read-only GitHub HTTP collection and synthetic contracts. Manual compatibility only.
- **M2:** journalled manual init/attach/adoption/detach; reviewed reversible extraction and exact index operations; grants/approval/validation/recovery.
- **M3:** tested real OMP/Codex probes, rendering, activation/switching, supervision, manifests and handovers; preserved replacement.
- **M4:** lifecycle/candidates/check receipts/human testing/sign-off/invalidation and controlled shipping.
- **M5:** optional semantics, other providers, shared packs, symlinks/cloud attachments, stronger privilege isolation and team interfaces when justified.

## Supported implementation limits

Linux trusted-local inspection, Python >=3.12; Git config includes fail closed. No historical Git traversal, submodule recursion, LFS downloading, symlink attachments, enterprise origins, saved-report audit freshness comparison, semantic enrichment, third-party trust-management command, full dynamic dependency analysis or complete lifecycle state model. Known ignored discovery paths are bounded exceptions; arbitrary ignored trees/ambient homes remain uninspected. Packaging independence uses separately executed evidence, never audit-side builds. Native Windows unsupported; macOS not yet exercised.

## References

[Git configuration](https://git-scm.com/docs/git-config), [ignore semantics](https://git-scm.com/docs/gitignore), [index enumeration](https://git-scm.com/docs/git-ls-files), [check-ignore](https://git-scm.com/docs/git-check-ignore), [worktrees](https://git-scm.com/docs/git-worktree), [uv locking](https://docs.astral.sh/uv/concepts/projects/sync/), [entry points](https://packaging.python.org/en/latest/specifications/entry-points/), [GitHub Actions API](https://docs.github.com/en/rest/actions/workflow-runs), [rules API](https://docs.github.com/en/rest/repos/rules), [API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions). Version-specific harness claims require actual adapter contracts rather than documentation links alone.
