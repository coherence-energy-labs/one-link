"""Persistence layer (state.py) tests — sqlite + FTS5 + CRUD."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import identity_dag as idag
from one_link import state as state_module
from one_link.state import MessageIdConflict, MessageQuotaExceeded, State


@pytest.fixture
def state(tmp_path: Path) -> State:
    s = State(db_path=tmp_path / "state.db")
    yield s
    s.close()


# ───────── peers ──────────────────────────────────────────────────────

def test_upsert_new_peer(state: State):
    rec = state.upsert_peer(
        fingerprint="ab" * 32,
        short_id="abababab",
        pubkey=b"\x00" * 32,
        hostname="alice",
    )
    assert rec.fingerprint == "ab" * 32
    assert rec.short_id == "abababab"
    assert rec.hostname == "alice"
    assert rec.trust == "pending"
    assert rec.first_seen_ms == rec.last_seen_ms


def test_upsert_existing_peer_updates_last_seen(state: State):
    fp = "ab" * 32
    a = state.upsert_peer(fingerprint=fp, short_id="abababab", pubkey=b"\x01" * 32)
    time.sleep(0.01)
    b = state.upsert_peer(fingerprint=fp, short_id="abababab", pubkey=b"\x01" * 32)
    assert b.last_seen_ms >= a.last_seen_ms
    assert b.first_seen_ms == a.first_seen_ms


def test_upsert_does_not_clobber_trust(state: State):
    fp = "ab" * 32
    state.upsert_peer(fingerprint=fp, short_id="ab", pubkey=b"\x00" * 32)
    state.set_peer_trust(fp, "pinned")
    state.upsert_peer(fingerprint=fp, short_id="ab", pubkey=b"\x00" * 32)
    assert state.get_peer(fp).trust == "pinned"


def test_set_peer_trust_validates(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="aa", pubkey=b"\x00" * 32)
    with pytest.raises(ValueError):
        state.set_peer_trust("aa" * 32, "yolo")
    state.set_peer_trust("aa" * 32, "rejected")
    assert state.get_peer("aa" * 32).trust == "rejected"


def test_get_peer_by_short_id(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="alice123", pubkey=b"\x00" * 32)
    rec = state.get_peer_by_short_id("alice123")
    assert rec and rec.fingerprint == "aa" * 32


def test_list_peers_orders_by_last_seen(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="a", pubkey=b"\x00" * 32)
    time.sleep(0.005)
    state.upsert_peer(fingerprint="bb" * 32, short_id="b", pubkey=b"\x00" * 32)
    out = state.list_peers()
    assert [p.short_id for p in out] == ["b", "a"]


# ───────── messages ───────────────────────────────────────────────────

def test_record_and_fetch_message(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="alice", pubkey=b"\x00" * 32)
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="hello world", metadata={"short_id": "alice"},
    )
    out = state.recent_messages(limit=10)
    assert len(out) == 1
    assert out[0].id == "m1"
    assert out[0].body == "hello world"
    assert out[0].direction == "in"


def test_recent_messages_filters_by_peer(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="a", pubkey=b"\x00" * 32)
    state.upsert_peer(fingerprint="bb" * 32, short_id="b", pubkey=b"\x00" * 32)
    state.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="from a")
    state.record_message(id="m2", ts_ms=2, direction="in", peer_fp="bb" * 32,
                         msg_type="TEXT", body="from b")
    only_a = state.recent_messages(peer_fp="aa" * 32, limit=10)
    assert [m.body for m in only_a] == ["from a"]


def test_record_message_idempotent(state: State):
    """Recording the same id twice should not duplicate."""
    state.upsert_peer(fingerprint="aa" * 32, short_id="a", pubkey=b"\x00" * 32)
    state.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="hi")
    state.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="hi")
    assert len(state.recent_messages(limit=10)) == 1


def test_record_message_rejects_same_id_with_different_payload(state: State):
    kwargs = dict(
        id="exact-conflict-1", ts_ms=1, direction="in",
        peer_fp="aa" * 32, msg_type="TEXT", body="first",
    )
    assert state.record_message(**kwargs) is True
    assert state.record_message(**kwargs) is False
    with pytest.raises(MessageIdConflict, match="reused for different content"):
        state.record_message(**{**kwargs, "body": "second"})


def test_record_message_exact_replay_survives_edit_and_delete(state: State):
    """Mutable presentation state cannot destroy immutable replay evidence."""
    kwargs = dict(
        id="exact-after-mutation-1", ts_ms=1, direction="in",
        peer_fp="aa" * 32, msg_type="TEXT", body="original",
    )
    assert state.record_message(**kwargs) is True
    assert state.edit_message(
        id=kwargs["id"], new_body="edited", edited_at_ms=2,
    ) is not None
    assert state.record_message(**kwargs) is False
    with pytest.raises(MessageIdConflict, match="reused for different content"):
        state.record_message(**{**kwargs, "body": "conflicting"})

    assert state.delete_message(id=kwargs["id"], deleted_at_ms=3) is not None
    assert state.record_message(**kwargs) is False
    with pytest.raises(MessageIdConflict, match="reused for different content"):
        state.record_message(**{**kwargs, "body": "conflicting"})


def test_text_quota_rejects_new_rows_but_allows_exact_replay(
    state: State, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(state_module, "MAX_TEXT_MESSAGES_PER_PEER", 1)
    first = dict(
        id="quota-message-1", ts_ms=1, direction="in",
        peer_fp="aa" * 32, msg_type="TEXT", body="first",
    )
    state.record_message(**first)
    assert state.record_message(**first) is False
    with pytest.raises(MessageQuotaExceeded, match="quota"):
        state.record_message(
            id="quota-message-2", ts_ms=2, direction="in",
            peer_fp="aa" * 32, msg_type="TEXT", body="second",
        )


def test_text_quota_counts_immutable_body_retained_by_first_edit(
    state: State, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(state_module, "MAX_TEXT_BODY_BYTES_PER_PEER", 8)
    state.record_message(
        id="quota-edit-1", ts_ms=1, direction="in",
        peer_fp="aa" * 32, msg_type="TEXT", body="12345",
    )
    # A first edit stores both the five-byte immutable original and the new
    # four-byte presentation body. It must not bypass the physical byte cap.
    with pytest.raises(MessageQuotaExceeded, match="quota"):
        state.edit_message(
            id="quota-edit-1", new_body="6789", edited_at_ms=2,
        )
    rec = state.get_message("quota-edit-1")
    assert rec is not None and rec.body == "12345"
    assert rec.original_body is None


def test_chat_quota_counts_control_message_metadata(
    state: State, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(state_module, "MAX_TEXT_BODY_BYTES_PER_PEER", 40)
    first = dict(
        id="quota-control-1", ts_ms=1, direction="in",
        peer_fp="aa" * 32, msg_type="EDIT_MSG", body=None,
        metadata={"body": "1234567890"},
    )
    assert state.record_message(**first) is True
    assert state.record_message(**first) is False
    with pytest.raises(MessageQuotaExceeded, match="quota"):
        state.record_message(**{**first, "id": "quota-control-2", "ts_ms": 2})


def test_durable_transaction_rolls_back_message_and_outbox_together(state: State):
    with pytest.raises(RuntimeError, match="inject rollback"):
        with state.durable_write_transaction():
            state.record_message(
                id="atomic-message-1", ts_ms=1, direction="out",
                peer_fp="aa" * 32, msg_type="TEXT", body="hello",
            )
            state.enqueue_outbox(
                peer_fp="aa" * 32,
                msg_id="atomic-message-1",
                msg_body={"t": "TEXT", "id": "atomic-message-1", "body": "hello"},
            )
            raise RuntimeError("inject rollback")
    assert state.get_message("atomic-message-1") is None
    assert state.list_outbox(peer_fp="aa" * 32) == []


def test_outbox_idempotency_rejects_payload_conflict(state: State):
    kwargs = dict(
        peer_fp="aa" * 32,
        msg_id="outbox-exact-1",
        msg_body={"t": "TEXT", "id": "outbox-exact-1", "body": "first"},
    )
    first_id = state.enqueue_outbox(**kwargs)
    assert state.enqueue_outbox(**kwargs) == first_id
    with pytest.raises(MessageIdConflict, match="reused for different content"):
        state.enqueue_outbox(
            **{**kwargs, "msg_body": {**kwargs["msg_body"], "body": "second"}},
        )


def test_outbox_at_least_once_receiver_dedups_t3h(state: State):
    """2026-05-21 audit T3-H contract test.

    The outbox enqueue path (``enqueue_outbox`` + a redelivery on
    reconnect) gives at-least-once semantics on the wire. Receivers
    MUST dedup by ``msg_id`` so a peer that ACKs after the sender
    already gave up + re-queued doesn't get the same message twice.
    Anchor that contract here: the same ``msg_id`` recorded N times
    yields exactly one row in ``messages``.
    """
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="alice",
        pubkey=b"\x01" * 32,
    )
    # Simulate three deliveries of the same outbox entry — the
    # contract is that the receiver's record_message dedups.
    for _attempt in range(3):
        state.record_message(
            id="outbox-redelivery-msg-1",
            ts_ms=1000,
            direction="in",
            peer_fp="aa" * 32,
            msg_type="TEXT",
            body="will only appear once",
        )
    rows = state.recent_messages(limit=10)
    assert len([m for m in rows if m.body == "will only appear once"]) == 1


# ───────── FTS5 search ────────────────────────────────────────────────

def test_search_messages(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="a", pubkey=b"\x00" * 32)
    state.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="the quick brown fox")
    state.record_message(id="m2", ts_ms=2, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="lazy dog jumps")
    state.record_message(id="m3", ts_ms=3, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="quick bunny")
    out = state.search_messages("quick")
    bodies = sorted(m.body for m in out)
    assert bodies == ["quick bunny", "the quick brown fox"]


def test_search_messages_with_peer_filter(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="a", pubkey=b"\x00" * 32)
    state.upsert_peer(fingerprint="bb" * 32, short_id="b", pubkey=b"\x00" * 32)
    state.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="hello")
    state.record_message(id="m2", ts_ms=2, direction="in", peer_fp="bb" * 32,
                         msg_type="TEXT", body="hello")
    out = state.search_messages("hello", peer_fp="aa" * 32)
    assert len(out) == 1
    assert out[0].peer_fp == "aa" * 32


# ───────── persistence across restart ─────────────────────────────────

def test_state_persists_across_close_and_reopen(tmp_path: Path):
    db = tmp_path / "state.db"
    s1 = State(db_path=db)
    s1.upsert_peer(fingerprint="aa" * 32, short_id="alice", pubkey=b"\x00" * 32)
    s1.set_peer_trust("aa" * 32, "pinned")
    s1.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                      msg_type="TEXT", body="persistent hello")
    s1.close()

    s2 = State(db_path=db)
    try:
        rec = s2.get_peer("aa" * 32)
        assert rec is not None
        assert rec.trust == "pinned"
        msgs = s2.recent_messages(limit=10)
        assert len(msgs) == 1
        assert msgs[0].body == "persistent hello"
    finally:
        s2.close()


# ───────── rooms / folders / blobs (smoke) ────────────────────────────

def test_create_and_get_room(state: State):
    state.create_room(room_id="r1", name="Family", members=["aa" * 32, "bb" * 32])
    r = state.get_room("r1")
    assert r["name"] == "Family"
    assert "aa" * 32 in r["members"]


def test_room_name_uniqueness(state: State):
    state.create_room(room_id="r1", name="A", members=[])
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        state.create_room(room_id="r2", name="A", members=[])


def test_add_remove_folder(state: State):
    state.add_folder(name="docs", local_path="/tmp/docs", shared_with=["aa" * 32])
    f = state.get_folder("docs")
    assert f["local_path"] == "/tmp/docs"
    assert state.folder_peer_allows("docs", "aa" * 32, "push")
    assert state.folder_peer_allows("docs", "aa" * 32, "pull")
    state.remove_folder("docs")
    assert state.get_folder("docs") is None


def test_share_folder_with(state: State):
    state.add_folder(name="docs", local_path="/tmp/docs", shared_with=[])
    state.share_folder_with("docs", "aa" * 32)
    state.share_folder_with("docs", "aa" * 32)  # idempotent
    state.share_folder_with("docs", "bb" * 32)
    members = state.get_folder("docs")["shared_with"]
    assert sorted(members) == sorted(["aa" * 32, "bb" * 32])
    state.set_folder_peer_permission("docs", "aa" * 32, "push")
    assert state.folder_peer_allows("docs", "aa" * 32, "push")
    assert not state.folder_peer_allows("docs", "aa" * 32, "pull")
    state.unshare_folder_with("docs", "aa" * 32)
    assert state.get_folder("docs")["shared_with"] == ["bb" * 32]
    assert state.get_folder_peer_permission("docs", "aa" * 32) is None


def test_manifest_upsert_and_list(state: State):
    state.add_folder(name="docs", local_path="/tmp/docs", shared_with=[])
    state.upsert_manifest_entry(
        folder_name="docs",
        file_path="hello.txt",
        blob_hash="ab" * 32,
        size=11,
        mtime_ms=12345,
        vclock={"aa" * 32: 1},
    )
    out = state.list_manifest("docs")
    assert len(out) == 1
    assert out[0]["file_path"] == "hello.txt"
    assert out[0]["blob_hash"] == "ab" * 32


def test_blob_record(state: State):
    state.record_blob("ab" * 32, 1024)
    assert state.has_blob("ab" * 32)
    assert not state.has_blob("cd" * 32)


# ───────── settings (kv) ──────────────────────────────────────────────

def test_set_get_setting(state: State):
    assert state.get_setting("foo") is None
    assert state.get_setting("foo", "default") == "default"
    state.set_setting("foo", "bar")
    assert state.get_setting("foo") == "bar"


def test_setting_upsert(state: State):
    state.set_setting("color", "red")
    state.set_setting("color", "blue")
    assert state.get_setting("color") == "blue"


def test_all_settings(state: State):
    state.set_setting("a", "1")
    state.set_setting("b", "2")
    out = state.all_settings()
    assert out == {"a": "1", "b": "2"}


def test_route_memory_roundtrips(state: State):
    state.upsert_route_memory(
        peer_fp="aa" * 32,
        route="lan",
        attempts=5,
        successes=4,
        failures=1,
        score=123.5,
        latency_ms=6.0,
        bandwidth_bps=750_000_000.0,
        metadata={"source": "test"},
    )

    rows = state.list_route_memory("aa" * 32)

    assert rows[0]["route"] == "lan"
    assert rows[0]["attempts"] == 5
    assert rows[0]["successes"] == 4
    assert rows[0]["failures"] == 1
    assert rows[0]["latency_ms"] == 6.0
    assert rows[0]["bandwidth_bps"] == 750_000_000.0
    assert rows[0]["metadata"]["source"] == "test"


def test_route_candidates_roundtrip_rank_and_prune(state: State):
    fp = "ab" * 32
    state.upsert_route_candidate(
        peer_fp=fp,
        route="lan",
        transport="tcp",
        host="10.0.0.8",
        port=17117,
        source="signed_bootstrap",
        verified=False,
        expires_ms=10,
        metadata={"hint": "qr"},
    )
    state.observe_route_candidate(
        peer_fp=fp,
        route="lan",
        transport="tcp",
        host="10.0.0.8",
        port=17117,
        ok=True,
        source="endpoint_verify",
        verified=True,
        latency_ms=4.0,
        bandwidth_bps=900_000_000.0,
        expires_ms=9999999999999,
    )
    state.observe_route_candidate(
        peer_fp=fp,
        route="relay",
        transport="tcp",
        host="relay.example",
        port=443,
        ok=False,
        source="runtime",
        error="timeout",
    )

    rows = state.list_route_candidates(fp, verified_only=True)

    assert rows[0]["host"] == "10.0.0.8"
    assert rows[0]["verified"] is True
    assert rows[0]["successes"] == 1
    assert rows[0]["metadata"]["hint"] == "qr"
    assert state.prune_route_candidates(now_ms=11) == 0
    assert state.prune_route_candidates(now_ms=99999999999999) == 1


def _ed25519_pair():
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def test_self_mesh_device_presence_and_replay_persist(tmp_path: Path):
    db = tmp_path / "state.db"
    root_seed, root_pub = _ed25519_pair()
    _, phone_pub = _ed25519_pair()
    _, laptop_pub = _ed25519_pair()
    cert = idag.encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=phone_pub,
        device_kind="phone-ios",
        added_ms=1000,
    )

    s1 = State(db_path=db)
    try:
        row = s1.upsert_self_mesh_device(
            root_pub=root_pub,
            device_pub=phone_pub,
            device_kind="phone-ios",
            cert=cert,
            label="Phone",
            local=True,
            metadata={"source": "test"},
            added_ms=1000,
        )
        assert row["label"] == "Phone"
        assert row["local"] is True
        assert row["metadata"]["source"] == "test"

        s1.upsert_self_mesh_device(
            root_pub=root_pub,
            device_pub=laptop_pub,
            device_kind="laptop-windows",
            label="Laptop",
            revoked=True,
            added_ms=1000,
        )
        active = s1.list_self_mesh_devices(root_pub=root_pub, include_revoked=False)
        assert [d["device_pub"] for d in active] == [phone_pub]

        older = s1.upsert_self_mesh_presence(
            device_pub=phone_pub,
            state="awake",
            sequence=4,
            updated_ms=2000,
            network="wifi",
            battery_pct=90,
            free_bytes=123,
            route="self_wifi",
        )
        assert older["state"] == "awake"
        stale = s1.upsert_self_mesh_presence(
            device_pub=phone_pub,
            state="offline",
            sequence=3,
            updated_ms=9999,
            network="offline",
        )
        assert stale["state"] == "awake"

        assert s1.mark_remote_instruction_seen(
            command_id="a" * 64,
            expires_ms=9000,
            action="pull_file_manifest",
            controller_device_pub=phone_pub,
            target_device_pub=laptop_pub,
            now_ms=3000,
        ) is True
        assert s1.mark_remote_instruction_seen(
            command_id="a" * 64,
            expires_ms=9000,
            now_ms=3001,
        ) is False
    finally:
        s1.close()

    s2 = State(db_path=db)
    try:
        assert s2.schema_version() >= 18
        devices = s2.list_self_mesh_devices(root_pub=root_pub)
        assert {d["label"] for d in devices} == {"Phone", "Laptop"}
        presence = s2.list_self_mesh_presence()
        assert presence[0]["device_pub"] == phone_pub
        assert presence[0]["state"] == "awake"
    finally:
        s2.close()


def test_self_mesh_root_revocation_and_audit_persist(tmp_path: Path):
    db = tmp_path / "state.db"
    root_seed, root_pub = _ed25519_pair()
    _, device_pub = _ed25519_pair()
    cert = idag.encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=device_pub,
        device_kind="tablet",
    )

    s1 = State(db_path=db)
    try:
        root = s1.upsert_self_mesh_root(
            root_pub=root_pub,
            root_seed=root_seed,
            label="My devices",
        )
        assert root["has_root_seed"] is True
        with_seed = s1.get_self_mesh_root(root_pub, include_seed=True)
        assert with_seed["root_seed"] == root_seed
        s1.upsert_self_mesh_device(
            root_pub=root_pub,
            device_pub=device_pub,
            cert=cert,
            device_kind="tablet",
            label="Tablet",
            local=False,
            trusted=True,
        )
        revoked = s1.revoke_self_mesh_device(
            root_pub=root_pub,
            device_pub=device_pub,
        )
        assert revoked["revoked"] is True
        assert revoked["trusted"] is False
        audit_id = s1.record_self_mesh_audit(
            event="device_revoked",
            severity="warn",
            root_pub=root_pub,
            device_pub=device_pub,
            detail="Tablet",
        )
        assert audit_id > 0
    finally:
        s1.close()

    s2 = State(db_path=db)
    try:
        assert s2.schema_version() >= 19
        assert s2.list_self_mesh_roots()[0]["label"] == "My devices"
        assert s2.list_self_mesh_devices(root_pub=root_pub)[0]["revoked"] is True
        assert s2.list_self_mesh_audit()[0]["event"] == "device_revoked"
        feed = s2.activity_feed(kinds=["self_mesh"])
        assert feed[0]["kind"] == "self_mesh"
        assert feed[0]["subkind"] == "device_revoked"
    finally:
        s2.close()


def test_self_mesh_root_seed_wrap_marker_collision_is_cleartext(tmp_path: Path):
    """A random 32-byte seed beginning 0x01 is not wrapped ciphertext."""
    root_seed = b"\x01" + bytes(range(1, 32))
    root_pub = Ed25519PrivateKey.from_private_bytes(
        root_seed
    ).public_key().public_bytes_raw()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_self_mesh_root(
            root_pub=root_pub,
            root_seed=root_seed,
            label="Marker collision",
        )

        stored = state._conn.execute(
            "SELECT root_seed FROM self_mesh_roots WHERE root_pub = ?",
            (root_pub,),
        ).fetchone()["root_seed"]
        assert bytes(stored) == root_seed
        restored = state.get_self_mesh_root(root_pub, include_seed=True)
        assert restored is not None
        assert restored["root_seed"] == root_seed
    finally:
        state.close()


def test_remote_instruction_replay_store_is_strict_bounded_and_fail_closed(
    tmp_path: Path,
    monkeypatch,
):
    from one_link import state as state_module

    state = State(db_path=tmp_path / "state.db")
    try:
        with pytest.raises(ValueError, match="lowercase SHA-256"):
            state.mark_remote_instruction_seen(
                command_id="not-a-digest",
                expires_ms=200,
                now_ms=100,
            )
        with pytest.raises(ValueError, match="expires_ms must be an integer"):
            state.mark_remote_instruction_seen(
                command_id="a" * 64,
                expires_ms=True,
                now_ms=100,
            )
        with pytest.raises(ValueError, match="retention limit"):
            state.mark_remote_instruction_seen(
                command_id="a" * 64,
                expires_ms=state_module.MAX_REMOTE_INSTRUCTION_REPLAY_RETENTION_MS + 101,
                now_ms=100,
            )

        monkeypatch.setattr(state_module, "MAX_REMOTE_INSTRUCTION_SEEN_ROWS", 1)
        assert state.mark_remote_instruction_seen(
            command_id="a" * 64,
            expires_ms=200,
            action="pull_file_manifest",
            now_ms=100,
        )
        assert not state.mark_remote_instruction_seen(
            command_id="a" * 64,
            expires_ms=200,
            now_ms=101,
        )
        with pytest.raises(RuntimeError, match="replay cache is full"):
            state.mark_remote_instruction_seen(
                command_id="b" * 64,
                expires_ms=200,
                now_ms=101,
            )

        # Expired evidence may be pruned, making capacity available without
        # ever evicting a still-live replay tombstone.
        assert state.mark_remote_instruction_seen(
            command_id="b" * 64,
            expires_ms=300,
            now_ms=201,
        )
        assert state._conn.execute(
            "SELECT command_id FROM remote_instruction_seen"
        ).fetchone()["command_id"] == "b" * 64
    finally:
        state.close()


def test_remote_instruction_replay_store_survives_reopen(tmp_path: Path):
    db = tmp_path / "state.db"
    first = State(db_path=db)
    try:
        assert first.mark_remote_instruction_seen(
            command_id="c" * 64,
            expires_ms=10_000,
            action="send_file_from_device",
            now_ms=1_000,
        )
    finally:
        first.close()

    second = State(db_path=db)
    try:
        assert not second.mark_remote_instruction_seen(
            command_id="c" * 64,
            expires_ms=10_000,
            action="send_file_from_device",
            now_ms=1_001,
        )
    finally:
        second.close()


def test_self_mesh_root_rejects_mismatched_seed_and_public_key(tmp_path: Path):
    root_seed, _ = _ed25519_pair()
    _, unrelated_pub = _ed25519_pair()
    state = State(db_path=tmp_path / "state.db")
    try:
        with pytest.raises(ValueError, match="root_seed does not match root_pub"):
            state.upsert_self_mesh_root(
                root_pub=unrelated_pub,
                root_seed=root_seed,
                label="Corrupt root",
            )
    finally:
        state.close()


def test_self_mesh_root_rejects_invalid_storage_envelope_length(tmp_path: Path):
    root_seed, root_pub = _ed25519_pair()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_self_mesh_root(
            root_pub=root_pub,
            root_seed=root_seed,
            label="Corrupt envelope",
        )
        state._conn.execute(
            "UPDATE self_mesh_roots SET root_seed = ? WHERE root_pub = ?",
            (b"\x01" + b"x" * 32, root_pub),
        )

        with pytest.raises(
            ValueError,
            match="invalid stored self-mesh root seed length",
        ):
            state.get_self_mesh_root(root_pub, include_seed=True)
    finally:
        state.close()


def test_device_guardian_state_and_hash_chain_persist(tmp_path: Path):
    db = tmp_path / "state.db"
    root_pub = b"r" * 32
    device_pub = b"d" * 32
    actor_pub = b"a" * 32
    s1 = State(db_path=db)
    try:
        s1.upsert_self_mesh_device(
            root_pub=root_pub,
            device_pub=device_pub,
            device_kind="phone",
            label="Phone",
            trusted=True,
        )
        frozen = s1.set_self_mesh_device_safety(
            root_pub=root_pub,
            device_pub=device_pub,
            requested_state="frozen",
            actor_device_pub=actor_pub,
            proofs=["recent_unlock"],
            reason="phone stolen",
            ts_ms=10_000,
        )
        assert frozen["ok"] is True
        assert frozen["device"]["safety_state"] == "frozen"
        assert frozen["device"]["trusted"] is False
        denied = s1.set_self_mesh_device_safety(
            root_pub=root_pub,
            device_pub=device_pub,
            requested_state="trusted",
            actor_device_pub=actor_pub,
            proofs=[],
            reason="mistake",
            ts_ms=11_000,
        )
        assert denied["ok"] is False
        assert denied["device"]["safety_state"] == "frozen"
        restored = s1.set_self_mesh_device_safety(
            root_pub=root_pub,
            device_pub=device_pub,
            requested_state="trusted",
            actor_device_pub=actor_pub,
            proofs=["recent_unlock"],
            reason="device recovered",
            ts_ms=12_000,
        )
        assert restored["ok"] is True
        assert restored["device"]["safety_state"] == "trusted"
    finally:
        s1.close()

    s2 = State(db_path=db)
    try:
        device = s2.get_self_mesh_device(root_pub=root_pub, device_pub=device_pub)
        assert device["safety_state"] == "trusted"
        events = list(reversed(s2.list_device_guardian_events(limit=10)))
        assert len(events) == 3
        assert events[0]["prev_hash"] == ""
        assert events[1]["prev_hash"] == events[0]["event_hash"]
        assert events[2]["prev_hash"] == events[1]["event_hash"]
    finally:
        s2.close()


def test_device_guardian_upsert_cannot_make_frozen_device_trusted(tmp_path: Path):
    db = tmp_path / "state.db"
    root_pub = b"r" * 32
    device_pub = b"d" * 32
    actor_pub = b"a" * 32
    state = State(db_path=db)
    try:
        state.upsert_self_mesh_device(
            root_pub=root_pub,
            device_pub=device_pub,
            device_kind="phone",
            label="Phone",
            trusted=True,
        )
        state.set_self_mesh_device_safety(
            root_pub=root_pub,
            device_pub=device_pub,
            requested_state="frozen",
            actor_device_pub=actor_pub,
            proofs=["recent_unlock"],
            reason="stolen",
        )
        row = state.upsert_self_mesh_device(
            root_pub=root_pub,
            device_pub=device_pub,
            device_kind="phone",
            label="Phone",
            trusted=True,
        )
        assert row["safety_state"] == "frozen"
        assert row["trusted"] is False
        assert row["revoked"] is False
    finally:
        state.close()


def test_self_mesh_performance_samples_are_bounded_and_persist(tmp_path: Path):
    db = tmp_path / "state.db"
    s1 = State(db_path=db)
    try:
        for i in range(3):
            sid = s1.record_self_mesh_perf_sample({
                "route_probe_runs": 10,
                "route_probe_ready": i,
                "route_probe_total_ms": 1.5 + i,
                "route_probe_avg_ms": 0.15 + i,
                "presence_rows": 2,
                "device_rows": 3,
                "recent_audit_rows": 4,
                "status": "ready",
            }, ts_ms=1000 + i)
            assert sid > 0
    finally:
        s1.close()

    s2 = State(db_path=db)
    try:
        assert s2.schema_version() >= 20
        samples = s2.list_self_mesh_perf_samples(limit=2)
        assert len(samples) == 2
        assert samples[0]["route_probe_ready"] == 2
        assert samples[0]["status"] == "ready"
    finally:
        s2.close()


def test_delete_setting(state: State):
    state.set_setting("k", "v")
    state.delete_setting("k")
    assert state.get_setting("k") is None


# ───────── deferred boot integrity check (dirty-bit) ───────────────
#
# PRAGMA quick_check on an encrypted 200 MB+ state.db is 13-18s of
# full-file decrypt. It used to run inline in State() on EVERY boot and
# dominated startup. It now runs ONLY after an unclean shutdown, off the
# boot path. These pin the dirty-bit state machine.


def test_first_boot_flags_integrity_check(tmp_path: Path):
    """A brand-new DB (no clean marker) is treated as needing a check."""
    s = State(db_path=tmp_path / "state.db")
    try:
        assert s._needs_integrity_check is True
        # The marker is absent during a run (removed on open).
        assert not s._clean_marker.exists()
    finally:
        s.close()


def test_clean_close_then_reopen_skips_check(tmp_path: Path):
    """Clean close writes the marker; the next open sees it, skips the
    check, and the deferred check is a no-op."""
    db = tmp_path / "state.db"
    s1 = State(db_path=db)
    s1.close()
    assert s1._clean_marker.exists(), "clean close must write the marker"

    s2 = State(db_path=db)
    try:
        assert s2._needs_integrity_check is False
        assert s2.run_deferred_integrity_check() == "skipped"
        # Opening removed the marker again (so a crash THIS run is caught).
        assert not s2._clean_marker.exists()
    finally:
        s2.close()


def test_unclean_shutdown_runs_check_and_passes(tmp_path: Path):
    """Simulate a crash: open cleanly, then abandon the next session
    WITHOUT State.close() (marker stays absent), reopen. The reopen
    flags the check; running it returns 'ok' on a healthy DB and then
    won't re-run until the next unclean boot."""
    db = tmp_path / "state.db"
    s1 = State(db_path=db)
    s1.set_setting("k", "v")  # write something real
    s1.close()  # clean — marker written

    # Crash sim: reopen (clears marker), then hard-close the raw conn
    # WITHOUT State.close() so the marker is never rewritten.
    s_crash = State(db_path=db)
    assert s_crash._needs_integrity_check is False  # prior close was clean
    s_crash._conn.close()  # hard close, NOT State.close() → no marker

    s2 = State(db_path=db)
    try:
        assert s2._needs_integrity_check is True
        assert s2.run_deferred_integrity_check() == "ok"
        # Second call is now a no-op for this run.
        assert s2.run_deferred_integrity_check() == "skipped"
        assert s2.get_setting("k") == "v"  # data intact
    finally:
        s2.close()


# ───────── folder_audit retention ─────────────────────────────────
#
# folder_audit is append-only AND the swarm-pull blob->peer index.
# Continuous sync appends a row per file per cycle, so uncapped it grew
# to ~400k rows / 222 MB. prune_folder_audit caps it, keeping the newest
# rows (so recent blob->peer mappings stay warm) and deleting the oldest
# in bounded batches.


def _seed_folder_audit(state: State, n: int) -> None:
    with state._write_lock:
        state._conn.executemany(
            "INSERT INTO folder_audit(ts_ms, folder_name, root_id, "
            "peer_fp, action, file_path) VALUES(?,?,?,?,?,?)",
            [(1000 + i, "f", "r", "aa" * 32, "write", f"file{i}.bin")
             for i in range(n)],
        )


def test_prune_folder_audit_caps_to_keep_max_in_batches(state: State):
    _seed_folder_audit(state, 5000)
    # keep_max=1000, batch=2000: each call deletes up to 2000 of the
    # oldest beyond the cap.
    deleted1 = state.prune_folder_audit(keep_max=1000, batch=2000)
    assert deleted1 == 2000
    deleted2 = state.prune_folder_audit(keep_max=1000, batch=2000)
    assert deleted2 == 2000  # 4000 over the cap; second batch clears more
    deleted3 = state.prune_folder_audit(keep_max=1000, batch=2000)
    assert deleted3 == 0  # now exactly at the cap
    remaining = state._conn.execute(
        "SELECT COUNT(*) FROM folder_audit"
    ).fetchone()[0]
    assert remaining == 1000
    # The NEWEST rows are the ones kept (highest ids / latest files).
    kept_paths = {
        r[0] for r in state._conn.execute(
            "SELECT file_path FROM folder_audit"
        ).fetchall()
    }
    assert "file4999.bin" in kept_paths  # newest kept
    assert "file0.bin" not in kept_paths  # oldest pruned


def test_prune_folder_audit_noop_below_cap(state: State):
    _seed_folder_audit(state, 50)
    assert state.prune_folder_audit(keep_max=20000) == 0
    assert state._conn.execute(
        "SELECT COUNT(*) FROM folder_audit"
    ).fetchone()[0] == 50


def test_short_id_lookup_prefers_the_pinned_peer_and_refuses_ambiguity(tmp_path):
    from one_link.state import State

    state = State(db_path=tmp_path / "shortid.db")
    try:
        friend, grinder, second_friend = "aa" * 32, "bb" * 32, "cc" * 32
        for fp, key in ((friend, b"\x01"), (grinder, b"\x02")):
            state.upsert_peer(fingerprint=fp, short_id="deadbeef", pubkey=key * 32)
        # Two unpinned keys share a short ID: neither can be meant.
        assert state.get_peer_by_short_id("deadbeef") is None
        state.set_peer_trust(friend, "pinned")
        # The pinned peer wins even though the other key was seen later.
        state.upsert_peer(fingerprint=grinder, short_id="deadbeef", pubkey=b"\x02" * 32)
        assert state.get_peer_by_short_id("deadbeef").fingerprint == friend
        # Two pinned peers with one short ID: only a fingerprint can tell them apart.
        state.upsert_peer(fingerprint=second_friend, short_id="deadbeef", pubkey=b"\x03" * 32)
        state.set_peer_trust(second_friend, "pinned")
        assert state.get_peer_by_short_id("deadbeef") is None
        assert state.get_peer_by_short_id("nope") is None
    finally:
        state.close()
