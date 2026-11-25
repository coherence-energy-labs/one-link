from types import SimpleNamespace

import pytest

from one_link.transfer_routes import (
    PayloadRouteAccounting,
    peer_stream_transport,
    resumed_share,
    validate_file_transport,
)


@pytest.mark.parametrize("name", ["auto", "tcp", "relay"])
def test_supported_selection_is_explicit(name):
    assert validate_file_transport(name) == name


@pytest.mark.parametrize("name", ["quic", "webrtc"])
def test_unqualified_payload_route_cannot_be_requested_as_success(name):
    with pytest.raises(ValueError, match="unsupported_file_transport"):
        validate_file_transport(name)


@pytest.mark.parametrize("name", [None, "", "TCP", "fabricated"])
def test_invalid_selection_rejected(name):
    with pytest.raises(ValueError, match="invalid_file_transport"):
        validate_file_transport(name)


def test_actual_peer_stream_is_not_relabelled_webrtc():
    assert peer_stream_transport(SimpleNamespace(regime="lan")) == "tcp"
    assert peer_stream_transport(SimpleNamespace(regime="internet")) == "tcp"
    assert peer_stream_transport(SimpleNamespace(regime="relay")) == "relay"
    assert peer_stream_transport(SimpleNamespace()) == "unknown"


def test_mixed_route_receipt_conserves_acknowledged_payload():
    counters = PayloadRouteAccounting("auto")
    counters.acknowledge("quic", 300)
    counters.fallbacks += 1
    counters.acknowledge("tcp", 100)
    counters.acknowledge("tcp", 25)
    receipt = counters.snapshot()
    assert receipt["payload_transport"] == "mixed"
    assert receipt["payload_bytes_by_transport"] == {"quic": 300, "tcp": 125}
    assert receipt["payload_chunks_by_transport"] == {"quic": 1, "tcp": 2}
    assert receipt["payload_fallbacks"] == 1
    assert receipt["payload_accounting_scope"] == "acknowledged_application_payload"
    receipt["payload_bytes_by_transport"]["tcp"] = 0
    assert counters.snapshot()["payload_bytes_by_transport"]["tcp"] == 125


def test_replayed_commit_has_no_new_payload_route():
    assert PayloadRouteAccounting("tcp").snapshot()["payload_transport"] == "none"


def test_snapshot_names_its_unit_and_its_window():
    counters = PayloadRouteAccounting("auto")
    counters.acknowledge("tcp", 60, 100)  # 100 file bytes, 60 after compression
    receipt = counters.snapshot()
    assert receipt["payload_bytes_unit"] == "encoded_payload_bytes"
    assert receipt["payload_accounting_window"] == "attempt"
    assert receipt["payload_bytes_by_transport"] == {"tcp": 60}
    assert receipt["payload_transfer_totals"]["wire_bytes"] == 60
    assert receipt["payload_transfer_totals"]["raw_bytes"] == 100
    assert counters.ledger_counters() == {"raw_bytes": 100, "wire_bytes": 60}


def test_uncompressed_lane_reports_equal_raw_and_encoded_bytes():
    counters = PayloadRouteAccounting("auto")
    counters.acknowledge("tcp", 100)
    assert counters.ledger_counters() == {"raw_bytes": 100, "wire_bytes": 100}


def test_next_attempt_keeps_its_own_window_and_carries_the_transfer():
    first = PayloadRouteAccounting("auto")
    first.acknowledge("quic", 300, 900)
    first.fallbacks += 1
    first.acknowledge("tcp", 100)
    ledger_row = SimpleNamespace(metadata=first.snapshot())

    second = PayloadRouteAccounting.continuing("auto", ledger_row)
    assert second.snapshot()["payload_transport"] == "none"
    assert second.ledger_counters() == {"raw_bytes": 1000, "wire_bytes": 400}
    second.acknowledge("tcp", 50, 80)
    receipt = second.snapshot()

    assert receipt["payload_transport"] == "tcp"
    assert receipt["payload_bytes_by_transport"] == {"tcp": 50}
    assert receipt["payload_chunks_by_transport"] == {"tcp": 1}
    assert receipt["payload_fallbacks"] == 0
    assert receipt["payload_transfer_totals"] == {
        "payload_transport": "mixed",
        "payload_bytes_by_transport": {"quic": 300, "tcp": 150},
        "payload_chunks_by_transport": {"quic": 1, "tcp": 2},
        "payload_fallbacks": 1,
        "raw_bytes": 1080,
        "wire_bytes": 450,
        "chunks": 3,
    }

    third = PayloadRouteAccounting.continuing("auto", SimpleNamespace(metadata=receipt))
    assert third.snapshot()["payload_transfer_totals"] == receipt["payload_transfer_totals"]


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {},
        # A row written before the totals existed: its per-attempt fields are
        # one attempt's, not the transfer's, and are not promoted to totals.
        {"payload_bytes_by_transport": {"tcp": 7}, "payload_chunks_by_transport": {"tcp": 1}},
        {"payload_transfer_totals": "damaged"},
        {"payload_transfer_totals": {
            "raw_bytes": -1, "payload_fallbacks": True,
            "payload_bytes_by_transport": {"tcp": "9"},
            "payload_chunks_by_transport": ["tcp"],
        }},
    ],
)
def test_row_without_usable_totals_starts_the_transfer_from_zero(metadata):
    counters = PayloadRouteAccounting.continuing("tcp", SimpleNamespace(metadata=metadata))
    assert counters.requested == "tcp"
    assert counters.ledger_counters() == {"raw_bytes": 0, "wire_bytes": 0}
    totals = counters.snapshot()["payload_transfer_totals"]
    assert totals["payload_transport"] == "none"
    assert totals["chunks"] == 0 and totals["payload_fallbacks"] == 0
    assert PayloadRouteAccounting.continuing("tcp").ledger_counters() == {
        "raw_bytes": 0, "wire_bytes": 0,
    }


@pytest.mark.parametrize("raw_bytes", [-1, True, 1.5, "8"])
def test_acknowledged_raw_bytes_must_be_a_count(raw_bytes):
    counters = PayloadRouteAccounting("auto")
    with pytest.raises(ValueError, match="non-negative integer"):
        counters.acknowledge("tcp", 8, raw_bytes)
    assert counters.snapshot()["payload_chunks_by_transport"] == {}


@pytest.mark.parametrize(
    ("skipped", "earlier", "resumed"),
    [(800, 500, 500), (100, 900, 100), (0, 900, 0), (800, 0, 0), (-5, 900, 0), (800, -5, 0)],
)
def test_resumed_share_is_bounded_by_what_was_skipped_and_what_was_sent(skipped, earlier, resumed):
    assert resumed_share(skipped, earlier) == resumed


def test_skipped_at_offer_separates_resumed_bytes_from_prior_knowledge():
    first = PayloadRouteAccounting("auto")
    for _ in range(3):
        first.acknowledge("tcp", 100)
    resumed = PayloadRouteAccounting.continuing("auto", SimpleNamespace(metadata=first.snapshot()))
    # The receiver holds 400 of 1000 bytes: 300 this transfer sent, 100 it knew.
    assert resumed.skipped_at_offer(400, 1000) == {
        "skipped_bytes": 100, "skipped_ratio": 0.1, "resumed_bytes": 300,
    }
    assert PayloadRouteAccounting("auto").skipped_at_offer(400, 1000) == {
        "skipped_bytes": 400, "skipped_ratio": 0.4, "resumed_bytes": 0,
    }
