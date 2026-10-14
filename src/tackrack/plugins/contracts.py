"""Trusted built-in source and pure detector contracts; no plugin auto-imports."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import httpx

from tackrack.domain.models import CollectionResult, SourceDescriptor, utc_now


@dataclass(frozen=True)
class SourceProbeRequest:
    root: Path
    remote_url: str | None = None


@dataclass(frozen=True)
class SourceProbeResult:
    eligible: bool
    reason: str
    identity: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CollectionRequest:
    root: Path
    offline: bool = True
    remote_url: str | None = None
    network_authorized: bool = False
    window_days: int = 30
    max_pages: int = 20
    max_records: int = 1000


@dataclass(frozen=True)
class SourceContext:
    clock: Callable[[], str] = utc_now
    http: httpx.Client | None = None


class SourcePlugin(Protocol):
    def describe(self) -> SourceDescriptor: ...
    def probe(self, request: SourceProbeRequest) -> SourceProbeResult: ...
    def collect(self, request: CollectionRequest, context: SourceContext) -> CollectionResult: ...
