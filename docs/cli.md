# Implemented command contract

```fish
tackrack scan PATH --offline --attachment auto --format json
tackrack audit PATH --offline --attachment none --format json
tackrack scan PATH --sources local-git,github --remote origin --allow-network
tackrack register NAME --project PATH --workbench COMPANION_PATH
tackrack register NAME --project PATH --workbench COMPANION_PATH --trust-policy
tackrack audit NAME --offline --profile manual
tackrack plugins list --format json
```

Path or registered-name subjects. An arbitrary nested repository is its own subject; a registered companion root resolves through its explicit binding to the product. `scan` and `audit` collect fresh evidence, never fix it, execute project checks or launch harnesses. `audit --fix` does not exist. Registration records one valid existing independent nested/external pair per physical checkout; it neither adds ignore rules nor repairs an index nor activates exports. `--trust-policy` explicitly trusts reviewed manifest data, not a grant/human candidate approval. Default registration does not trust observed policy. Trust binds the manifest digest. Bindings are immutable in this foundation: rebinding, removal and trust refresh after material changes are not implemented. Manual context must be read explicitly.

`--attachment auto`: static bounded manifest/authored policy/profile/tool sources and known active export paths, including unregistered ignored real directories, without trust/activation. Unrelated top-level companion files are not parsed. `none`: slot metadata/index leaks only. `full`: expands ordinary companion files but still excludes .git payloads, runtime .local, dependency installs, caches, credential files and raw sessions/transcripts. Symlink slots are recorded without following targets. An explicit binding supports physically external companions, without relative sibling assumptions.

`--sources auto`: local always; eligible product GitHub remote only when `--allow-network` authorises public API reads. No network by default. `--offline` prohibits all network. Multiple plausible remotes are not guessed; choose `--remote`. Enterprise origins are unsupported. Credentials only via explicitly named `TACKRACK_GITHUB_TOKEN`; never argv/config/output. No other ambient token or CLI auth helper is used. GitHub API version 2026-03-10: identity, Actions summaries, visible rulesets and workflow definition references. Definitions record symbolic default refs/paths, not YAML bytes or an immutable commit. PR/integration-policy coverage is unsupported. Thirty-day run window, twenty pages/one thousand records per capability, at most one hundred ruleset detail requests, 120-second operation budget, no workflow source/log download.

`--include-ignored` expands ordinary product ignored content subject to bounds. Default scans inventory untracked and parse bounded ordinary/tracked content plus known ignored root/provider discovery paths. Active-looking filenames in inert source strings/fixtures/templates are not discovery surfaces. Nested active paths not ignored by Git are inspected, including src/tests; arbitrary ignored subtrees may remain unseen. Limits: 100,000 paths, 2 MiB per file, 256 MiB total parsed text, depth 16 for filesystem recursion. Large/missing objects and unsupported includes become explicit partial coverage. Static relationships and mixed-span suggestions never authorise extraction.

`--format json`: one JSON stdout envelope, no ANSI; status/coverage/evidence/findings/verdicts/artifacts/errors/exit code. `text` and `markdown` share the human-readable Markdown report. `--out NEW_EXTERNAL_PATH`: suffix .json stores JSON, otherwise Markdown, refuses existing outputs and paths inside inspected repositories/Git metadata. Private receipts also saved to external state blobs; ordinary report outputs contain redacted bounded excerpts, never raw credentials. NO_COLOR is respected by plain output. Unknown commands fail, never simulated success.

JSON timestamps remain UTC. Readable reports use the registered binding's display timezone; the bootstrap binding records `Australia/Hobart`. Unregistered reports display UTC. No timezone preference is committed into the shared companion.

Verdicts independently expose product Git boundary, committed boundary, local containment, manual profile configuration, unverified product independence and attachment trust. A static pass never asserts absent ambient inputs or passing product builds. Activity is configured/referenced/observed/enforced independently; observed/enforced remain unknown without execution receipts. Optional remote/ambient gaps do not fail local-only policy; required local/profile gaps produce inconclusive.

Exit 0 within-scope pass/completion; 1 policy failure; 2 invocation/config/schema failure; 3 required coverage/capability inconclusive; 4 unstable scan. Auth/grant/gate and supervised child-process exit semantics belong to future implemented slices (spec reserves 5/6/130). A stable scan means no relevant observed changes during collection; it is not a transactional filesystem snapshot. Saved reports are historical records, not executable plans; saved-scan audit freshness comparison is not implemented.

Defaults are platform user dirs; absolute config/state/cache overrides must be external. Only SQLite bindings/inspection receipts/historical agent notes are implemented. No approvals, migration, init/attach/switch/detach, profile probing, runs, lifecycle or shipping commands exist yet.

## Initial rule coverage

The foundation evaluates discovery/index leaks (`TR-A001`, `TR-A017`, `TR-A018`, `TR-A019`), mixed spans (`TR-A003`), static resource/reference validation (`TR-A008`), missing local coverage (`TR-A009`), redaction (`TR-A010`), named hosted workflow declarations/revision mismatches (`TR-A013`, `TR-A015`), live-looking profile payloads (`TR-A020`) and narrow executable/config companion dependencies (`TR-A021`). Manual unsupported/version-unverified assessment emits `TR-A006`. Inert credential-like test data remains product-owned, redacted, informational and review-only; it is not an active discovery surface. These heuristics are not the full future audit catalogue. Generated-output manifests, approvals/candidates, bridge exceptions, extraction-consumer resolution and effective harness enforcement require later implemented state/adapter slices.

Known hosted development-agent callers currently include [Claude Code Action](https://github.com/anthropics/claude-code-action) and [Codex Action](https://github.com/openai/codex-action). Their local workflow declarations are parsed with a safe, duplicate-rejecting YAML loader; quoted examples in run blocks are not callers. Unsupported/truncated workflow semantics are inconclusive, not proof of no AI automation. Discovery is catalogue-scoped, not universal dynamic CI analysis.
