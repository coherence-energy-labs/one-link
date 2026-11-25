from types import SimpleNamespace

import pytest

from one_link.transfer_routes import (
    PayloadRouteAccounting,
    peer_stream_transport,
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
