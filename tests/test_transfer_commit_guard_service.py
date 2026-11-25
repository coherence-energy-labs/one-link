"""Retry accounting through the guard's explicit ledger and durability ports."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from one_link.namespace_durability import replace_path
from one_link.transfer_commit_guard import RemoteCommitGuard


def record():
    contract = {
        "schema": 1,
        "transfer_id": "t1",
        "delivery_id": "nonce",
        "peer_fp": "ab" * 32,
        "blob": "cd" * 32,
        "size": 17,
        "name": "file.bin",
        "rel_path": "folder/file.bin",
        "kind": "file",
        "mode": "cdc",
        "receipt_capable": True,
    }
    metadata = {
        "offer_boundary_committed": True,
        "offer_boundary_contract": copy.deepcopy(contract),
        "delivery_id": contract["delivery_id"],
        "delivery_name": contract["name"],
        "delivery_rel_path": contract["rel_path"],
        "delivery_kind": contract["kind"],
        "receipt_capable": True,
    }
    return SimpleNamespace(
        direction="out",
        peer_fp=contract["peer_fp"],
        blob_hash=contract["blob"],
        size=17,
        name="file.bin",
        metadata=metadata,
    ), contract


class Ledger:
    def __init__(self, root: Path, value):
        self.db_path = root / "state.db"
        self.value = value
        self.reads = 0

    def get_transfer(self, id):
        assert id == "t1"
        self.reads += 1
        return self.value


def test_stable_unknown_outcome_uses_one_ledger_snapshot(tmp_path):
    row, contract = record()
    ledger = Ledger(tmp_path, row)
    synced = []
    guard = RemoteCommitGuard(ledger, sync_parent=synced.append)
    guard.write("t1", delivery=contract)
    assert synced == [guard.path("t1")]
    assert guard.is_failstopped("t1") is False
    assert ledger.reads == 1
    guard.clear("t1")
    assert not guard.path("t1").exists()
    assert len(synced) == 2


def test_missing_ledger_is_blocked_but_a_known_pristine_row_can_start(tmp_path):
    guard = RemoteCommitGuard(None, sync_parent=lambda _: None)
    assert guard.is_failstopped("t1") is True
    row, _ = record()
    row.metadata = {}
    guard = RemoteCommitGuard(Ledger(tmp_path, row), sync_parent=lambda _: None)
    assert guard.is_failstopped("t1") is False
    guard.ledger.value = None
    assert guard.is_failstopped("t1") is True


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema", 2),
        ("transfer_id", "other"),
        ("delivery_id", "other"),
        ("peer_fp", "other"),
        ("blob", "other"),
        ("size", True),
        ("name", "other"),
        ("rel_path", "other"),
        ("kind", "other"),
        ("mode", "unknown"),
        ("receipt_capable", False),
    ],
)
def test_durable_boundary_contract_drift_blocks_retry(tmp_path, key, value):
    row, contract = record()
    guard = RemoteCommitGuard(Ledger(tmp_path, row), sync_parent=lambda _: None)
    guard.write("t1", delivery=contract)
    row.metadata["offer_boundary_contract"][key] = value
    assert guard.is_failstopped("t1") is True


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"schema": 1, "transfer_id": "other"},
        {"schema": 1, "transfer_id": "t1", "phase": "unknown"},
    ],
)
def test_malformed_marker_never_grants_retry(tmp_path, payload):
    row, _ = record()
    guard = RemoteCommitGuard(Ledger(tmp_path, row), sync_parent=lambda _: None)
    marker = guard.path("t1")
    marker.parent.mkdir()
    marker.write_text(json.dumps(payload))
    assert guard.is_failstopped("t1") is True


def test_remote_receipt_blocks_automatic_resend_even_if_ledger_was_lost(tmp_path):
    guard = RemoteCommitGuard(Ledger(tmp_path, None), sync_parent=lambda _: None)
    guard.write("t1", receipt={"committed": True})
    assert guard.is_failstopped("t1") is True


def test_marker_publication_precedes_parent_sync_and_cleans_temporary_file(tmp_path):
    row, _ = record()
    events = []

    def publish(source, destination):
        assert json.loads(source.read_text())["phase"] == "remote_committed"
        replace_path(source, destination)
        events.append("publish")

    def sync(path):
        assert path.is_file()
        events.append("sync")
        raise OSError("injected directory sync failure")

    guard = RemoteCommitGuard(Ledger(tmp_path, row), sync_parent=sync, replace=publish)
    with pytest.raises(OSError, match="injected"):
        guard.write("t1", receipt={"committed": True})
    assert events == ["publish", "sync"]
    assert list(guard.path("t1").parent.iterdir()) == [guard.path("t1")]
    assert guard.is_failstopped("t1") is True


@pytest.mark.parametrize("direction", ["in", "unknown", ""])
def test_guard_never_grants_an_outbound_retry_for_another_record_direction(tmp_path, direction):
    row, _ = record()
    row.direction = direction
    row.metadata = {}
    guard = RemoteCommitGuard(Ledger(tmp_path, row), sync_parent=lambda _: None)
    assert guard.is_failstopped("t1") is True
