"""Explicit file-payload route selection and acknowledgement accounting.

These counters measure acknowledged application payload bytes. They exclude
transport framing, encryption overhead, retransmissions and control traffic;
they are never described as packet-capture wire-byte measurements.

Two windows are kept apart, and every snapshot names both:

* the ATTEMPT: what the ``send_file`` call in progress put on a transport.
  A benchmark that times one call reads this.
* the TRANSFER: every attempt of one ledger delivery, this one included.  A
  paused send that resumes, or a retry that sends again, has moved more than
  its last attempt did; the ledger row reports the transfer.  A chunk the
  application sends again on a later attempt is acknowledged again and is
  counted again here; only the transport's own retransmissions are excluded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


PAYLOAD_ACCOUNTING_SCOPE = "acknowledged_application_payload"
#: Unit of ``payload_bytes_by_transport`` and of every ``wire_bytes`` total: a
#: chunk's payload as handed to the transport, after optional compression and
#: before encryption and framing.  The send path sums the same quantity into
#: ``wire_bytes_sent``.  ``raw_bytes`` is the file bytes that payload carried;
#: the two agree on every lane that does not compress.
PAYLOAD_BYTES_UNIT = "encoded_payload_bytes"
PAYLOAD_ATTEMPT_WINDOW = "attempt"
TRANSFER_TOTALS_KEY = "payload_transfer_totals"
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


def resumed_share(skipped_bytes: int, earlier_raw_bytes: int) -> int:
    """How much of what an attempt skipped an earlier attempt had delivered.

    ``skipped_bytes`` is payload the receiver already held when it answered
    this attempt's offer.  Whatever earlier attempts of the SAME transfer
    delivered is inside that figure, and the network carried it: it was
    resumed, not saved.  Earlier bytes the receiver did not keep are not
    skipped at all (a stream retry sends everything again), so the share is
    bounded by both numbers.  When the receiver kept only part of an earlier
    attempt the split favours "resumed": prior knowledge can be understated,
    never overstated.
    """
    return min(max(0, int(skipped_bytes)), max(0, int(earlier_raw_bytes)))


def _count(value: Any) -> int:
    """A persisted counter, or zero when the ledger value is not one."""
    return value if type(value) is int and value >= 0 else 0


def _counts(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {str(name): count for name, count in value.items() if type(count) is int and count >= 0}


def _merged(earlier: dict[str, int], current: dict[str, int]) -> dict[str, int]:
    return {
        name: earlier.get(name, 0) + current.get(name, 0)
        for name in sorted({*earlier, *current})
    }


def _route_label(chunks_by_transport: dict[str, int]) -> str:
    routes = sorted(name for name, chunks in chunks_by_transport.items() if chunks > 0)
    return routes[0] if len(routes) == 1 else "mixed" if routes else "none"


@dataclass
class PayloadRouteAccounting:
    requested: str = "auto"
    bytes_by_transport: dict[str, int] = field(default_factory=dict)
    chunks_by_transport: dict[str, int] = field(default_factory=dict)
    fallbacks: int = 0
    raw_bytes: int = 0
    #: What the transfer's earlier attempts moved, as its ledger row recorded.
    earlier_raw_bytes: int = 0
    earlier_bytes_by_transport: dict[str, int] = field(default_factory=dict)
    earlier_chunks_by_transport: dict[str, int] = field(default_factory=dict)
    earlier_fallbacks: int = 0

    @classmethod
    def continuing(cls, requested: str, ledger_row: Any = None) -> "PayloadRouteAccounting":
        """Accounting for the next attempt of the transfer ``ledger_row`` holds.

        Every acknowledged chunk rewrites the row's snapshot, so the totals
        found there already cover a paused or crashed attempt up to its last
        acknowledgement; nothing has to be handed over when an attempt dies.
        A row written before these totals existed starts from zero.
        """
        totals = (getattr(ledger_row, "metadata", None) or {}).get(TRANSFER_TOTALS_KEY)
        if not isinstance(totals, dict):
            return cls(requested)
        return cls(
            requested,
            earlier_raw_bytes=_count(totals.get("raw_bytes")),
            earlier_bytes_by_transport=_counts(totals.get("payload_bytes_by_transport")),
            earlier_chunks_by_transport=_counts(totals.get("payload_chunks_by_transport")),
            earlier_fallbacks=_count(totals.get("payload_fallbacks")),
        )

    def acknowledge(
        self, transport: str, payload_bytes: int, raw_bytes: int | None = None,
    ) -> None:
        """Count one acknowledged chunk on the transport that carried it.

        ``payload_bytes`` is the encoded payload (:data:`PAYLOAD_BYTES_UNIT`).
        ``raw_bytes`` is the file bytes it carried; a lane that never
        compresses omits it and the two are equal.
        """
        raw = payload_bytes if raw_bytes is None else raw_bytes
        for value in (payload_bytes, raw):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("acknowledged payload bytes must be a non-negative integer")
        self.bytes_by_transport[transport] = self.bytes_by_transport.get(transport, 0) + payload_bytes
        self.chunks_by_transport[transport] = self.chunks_by_transport.get(transport, 0) + 1
        self.raw_bytes += raw

    def transfer_totals(self) -> dict[str, Any]:
        """Every attempt of this transfer, the one in progress included."""
        bytes_by_transport = _merged(self.earlier_bytes_by_transport, self.bytes_by_transport)
        chunks_by_transport = _merged(self.earlier_chunks_by_transport, self.chunks_by_transport)
        return {
            "payload_transport": _route_label(chunks_by_transport),
            "payload_bytes_by_transport": bytes_by_transport,
            "payload_chunks_by_transport": chunks_by_transport,
            "payload_fallbacks": self.earlier_fallbacks + self.fallbacks,
            "raw_bytes": self.earlier_raw_bytes + self.raw_bytes,
            "wire_bytes": sum(bytes_by_transport.values()),
            "chunks": sum(chunks_by_transport.values()),
        }

    def ledger_counters(self) -> dict[str, int]:
        """The ledger row's ``raw_bytes`` and ``wire_bytes`` columns.

        The row is the transfer, so both cover every attempt.  Passing them
        on each write also keeps a new attempt's planning write from zeroing
        what earlier attempts moved.
        """
        totals = self.transfer_totals()
        return {"raw_bytes": totals["raw_bytes"], "wire_bytes": totals["wire_bytes"]}

    def skipped_at_offer(self, skipped_bytes: int, size: int) -> dict[str, int | float]:
        """Ledger fields for what the receiver already held at this offer.

        ``skipped_bytes`` is what it knew before this transfer began; the part
        an earlier attempt delivered is ``resumed_bytes`` and is not a saving.
        """
        resumed = resumed_share(skipped_bytes, self.earlier_raw_bytes)
        known = max(0, int(skipped_bytes)) - resumed
        return {
            "skipped_bytes": known,
            "skipped_ratio": round(known / max(1, int(size)), 6),
            "resumed_bytes": resumed,
        }

    def snapshot(self) -> dict[str, Any]:
        """This attempt's routes, labelled, beside the whole transfer's."""
        return {
            "transport_requested": self.requested,
            "payload_transport": _route_label(self.chunks_by_transport),
            "payload_bytes_by_transport": dict(sorted(self.bytes_by_transport.items())),
            "payload_chunks_by_transport": dict(sorted(self.chunks_by_transport.items())),
            "payload_fallbacks": self.fallbacks,
            "payload_accounting_scope": PAYLOAD_ACCOUNTING_SCOPE,
            "payload_bytes_unit": PAYLOAD_BYTES_UNIT,
            "payload_accounting_window": PAYLOAD_ATTEMPT_WINDOW,
            TRANSFER_TOTALS_KEY: self.transfer_totals(),
        }
