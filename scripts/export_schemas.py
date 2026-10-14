"""Export public versioned schemas; run with uv run --locked python scripts/export_schemas.py."""

from __future__ import annotations

import json
from pathlib import Path

from tackrack.domain.models import CollectionResult, Report, Snapshot
from tackrack.plugins.manual import Manifest, ManualProfile

if __name__ == "__main__":
    destination = Path(__file__).resolve().parents[1] / "src/tackrack/schemas"
    destination.mkdir(exist_ok=True)
    for name, model in (
        ("report", Report),
        ("snapshot", Snapshot),
        ("collection", CollectionResult),
        ("companion-manifest", Manifest),
        ("manual-profile", ManualProfile),
    ):
        path = destination / f"{name}-v1.json"
        path.write_text(
            json.dumps(model.model_json_schema(), sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        print(path.name)
