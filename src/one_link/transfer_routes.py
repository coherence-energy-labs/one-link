"""Explicit file-payload route selection and acknowledgement accounting.

These counters measure acknowledged application payload bytes. They exclude
transport framing, encryption overhead, retransmissions and control traffic;
they are never described as packet-capture wire-byte measurements.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


PAYLOAD_ACCOUNTING_SCOPE = "acknowledged_application_payload"
_REQUESTS = frozenset({"auto", "tcp", "relay", "webrtc", "quic"})


def validate_file_transport(requested: str) -> str:
    if not isinstance(requested, str) or requested not in _REQUESTS:
        raise ValueError("invalid_file_transport: expected auto, tcp, relay, webrtc, or quic")
    # The browser DataChannel transfer and native QUIC primitives are distinct
    # capabilities. The desktop send_file API currently qualifies its encrypted
    # peer stream only; a benchmark must not relabel it or enable an experimental
    # payload lane by requesting a transport name.
    if requested in {"webrtc", "quic"}:
        raise ValueError(f"unsupported_file_transport: {requested} file payload is not qualified")
    return requested


def peer_stream_transport(session: Any) -> str:
    regime = getattr(session, "regime", "unknown")
    if regime == "relay":
        return "relay"
    if regime in {"lan", "internet"}:
        return "tcp"
    writer = getattr(getattr(session, "channel", None), "writer", None)
    if writer is not None and callable(getattr(writer, "get_extra_info", None)):
        if writer.get_extra_info("socket") is not None:
            return "tcp"
    return "unknown"


@dataclass
class PayloadRouteAccounting:
    requested: str = "auto"
    bytes_by_transport: dict[str, int] = field(default_factory=dict)
    chunks_by_transport: dict[str, int] = field(default_factory=dict)
    fallbacks: int = 0

    def acknowledge(self, transport: str, payload_bytes: int) -> None:
        if isinstance(payload_bytes, bool) or not isinstance(payload_bytes, int) or payload_bytes < 0:
            raise ValueError("acknowledged payload bytes must be a non-negative integer")
        self.bytes_by_transport[transport] = self.bytes_by_transport.get(transport, 0) + payload_bytes
        self.chunks_by_transport[transport] = self.chunks_by_transport.get(transport, 0) + 1

    def snapshot(self) -> dict[str, Any]:
        routes = sorted(self.chunks_by_transport)
        return {
            "transport_requested": self.requested,
            "payload_transport": routes[0] if len(routes) == 1 else "mixed" if routes else "none",
            "payload_bytes_by_transport": dict(sorted(self.bytes_by_transport.items())),
            "payload_chunks_by_transport": dict(sorted(self.chunks_by_transport.items())),
            "payload_fallbacks": self.fallbacks,
            "payload_accounting_scope": PAYLOAD_ACCOUNTING_SCOPE,
        }
