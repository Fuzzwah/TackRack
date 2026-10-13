# Ordinary product development

Python 3.12 minimum; bootstrap development interpreter Python 3.13.5. Install uv (bootstrap used 0.9.5) separately through approved tooling. Product dependencies are locked in `uv.lock`; Hatchling is pinned separately to 1.27.0 for isolated builds.

```fish
uv sync --locked
uv run --locked python -m tackrack --help
uv run --locked pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy src
python3 scripts/check_boundary.py
uv build --no-sources
python3 scripts/check_boundary.py --artifact dist/tackrack-0.1.0-py3-none-any.whl --artifact dist/tackrack-0.1.0.tar.gz
```

No companion or AI credentials are needed. CI uses Python 3.12/3.13, locked sync, pinned action revisions and normal product checks. Explicit test roots keep real user state and companion out of tests. Tests create temporary Git repositories and synthetic HTTP/harness data; no live provider credentials.

Tests/linters/types/package selection must not recursively consume the real `.agents`. Never stage it or create a submodule/gitlink. Do not use broad `git clean` against a checkout with an ignored companion. Git inside the companion targets a different repository.

Inspect normal requirements/resources and maintain product docs here; operational AI guidance is companion-owned. Use `vi docs/cli.md` when editing from a Linux terminal. Existing specifications/history and shared checks remain product-owned. No licence/publishing authority is assumed. A locked sync/install and active project checks are distinct from permission to fetch companions, start harnesses or ship.

For isolated state use absolute `TACKRACK_CONFIG_DIR`, `TACKRACK_STATE_DIR`, `TACKRACK_CACHE_DIR` locations outside inspected product, companion and their Git directories. Each is distinct; nested overrides are rejected before mutation. Preserve ledger, referenced blobs, bootstrap provenance and parked work together when backing up. There is no rollback data or parked companion in M1; future recovery material must not be pruned as cache.

Public schema-v1 JSON Schemas ship in `src/tackrack/schemas`. Regenerate after an intentional model-contract change with `uv run --locked python scripts/export_schemas.py`. A fresh wheel environment should install runtime dependencies from `uv export --locked --no-dev --no-emit-project` using its hash-locked requirements and approved lockfile registry, then install the wheel with `--no-deps`. Product-source and synthetic attached/absent/external acceptance runs are separate from static audit; the latter never runs builds itself.
