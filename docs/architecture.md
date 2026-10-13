# Implemented architecture

- `domain/models.py`: strict schema-v1 provider-neutral Pydantic records; canonical identity helpers.
- `application/inspection.py`: local/attachment/hosting collection orchestration, built-in boundary audit and validated registration. No target writer, execution runner or shipping service.
- `infrastructure/git.py`: safe allowlisted Git broker; independent configs screened before invocation, sanitized environment, no optional writes/lazy fetch/execution hooks. Includes fail closed.
- `plugins/sources/local_git.py`: separate HEAD/index/working manifests, bounded non-following file reads, ignored discovery exceptions and exact root attachment partition with tracked leaks visible. Private fresh-scan witnesses cover the full operation, including the hosting/evaluation interval; no witnesses are imported from saved reports.
- `infrastructure/http.py`, `plugins/sources/github.py`: exact-origin GitHub HTTP broker and normalized per-capability collection.
- `plugins/detectors.py`: pure static discovery, mixed-prose proposals and reference edges. No fetch/execute/mutation API.
- `plugins/manual.py`: portable manifest validation and no-process manual compatibility.
- `infrastructure/state.py`: schema-v1 SQLite binding/inspection/note store, private immutable report blobs, external user roots. No approvals are inferred from notes.
- `cli/`: only working commands and shared report renderers. `plugins list` imports no third-party entry points.
- `scripts/check_boundary.py`: independent defence-in-depth guard, not an audit wrapper; own Git and artifact checks.

The scanner records bounded static evidence, not equivalent harness behavior or hostile-code isolation. Domain does not import Typer, HTTPX, a hosting SDK or harness package. Providers return the same normalized records. Report fingerprints exclude timestamps; observation metadata retains timestamps separately. SQLite is one authoritative operational registry; JSON blobs/exports are immutable views, not a second writable ledger. Bootstrap historical notes retain agent provenance and never become approvals.
