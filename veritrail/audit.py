"""
veritrail.audit
===============
Structured audit events for SIEM / observability pipelines.

Veritrail emits a structured event for every consequential operation
(delegation issued, action verified, revocation, integrity check). Field names
follow the OpenTelemetry GenAI semantic conventions where one exists
(``gen_ai.agent.id``, ``gen_ai.operation.name``, ``gen_ai.tool.name``) so the
events drop straight into an OTel collector, Datadog, Splunk, or Elastic
without remapping. Veritrail-specific fields use the ``veritrail.*`` namespace.

By default no event sink is attached (``NullSink``). Attach :class:`JsonlSink`
to write newline-delimited JSON, or implement the one-method protocol to bridge
to your tracer. Sinks must never raise into the caller — an observability
failure must not break an authorization decision.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from typing import Any, Protocol, TextIO


class AuditSink(Protocol):
    def emit(self, event: dict[str, Any]) -> None: ...


class NullSink:
    """Discards events. The safe default."""

    def emit(self, event: dict[str, Any]) -> None:  # noqa: D401
        return None


class JsonlSink:
    """Writes newline-delimited JSON. Thread-safe; never raises into callers."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stdout
        self._lock = threading.Lock()

    def emit(self, event: dict[str, Any]) -> None:
        try:
            line = json.dumps(event, separators=(",", ":"), default=str)
            with self._lock:
                self._stream.write(line + "\n")
                self._stream.flush()
        except Exception:
            # Observability must not break authorization.
            pass


def make_event(operation: str, **fields: Any) -> dict[str, Any]:
    """Build an OTel-GenAI-flavored event envelope."""
    event = {
        "timestamp": time.time(),
        "gen_ai.operation.name": operation,
        "veritrail.event": operation,
    }
    event.update(fields)
    return event
