"""v0.21.x social-share recovery (guardian side).

Pin the guardian-side store of recovery shares: state schema,
import endpoint, list/delete endpoints, UI wiring. The third
restore path - users distribute Shamir shares, each guardian
holds one, and when the owner needs to recover they collect K
shares back from K guardians.

This file covers ship 1 (state + import/list/delete + UI card).
Ships 2 + 3 cover unwrap + recoverer-side combine.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]


def _server_src() -> str:
    return (ROOT / "src" / "one_link" / "server.py").read_text(encoding="utf-8")


def _index_html() -> str:
    return (ROOT / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")


def _open_state(tmp_path):
    from one_link.state import State
    return State(tmp_path / "state.db")


def _make_wrapped_share(*, threshold_k=3, total_n=5) -> bytes:
    """Mint a real .olss-shaped share for a fresh seed + dummy
    guardian keys. Returns the wire bytes of share #1."""
    from one_link import social_recovery
    seed = os.urandom(32)
    guardian_pubs = [
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        for _ in range(total_n)
    ]
    shares = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=guardian_pubs,
        threshold_k=threshold_k,
        total_n=total_n,
    )
    return shares[0].encoded


# ── state schema + helpers ──────────────────────────────────────────


def test_insert_held_share_persists_metadata_and_blob(tmp_path):
    state = _open_state(tmp_path)
    blob = _make_wrapped_share()
    row_id = state.insert_held_share(
        share_index=1, threshold_k=3, total_n=5,
        setup_ms=1_700_000_000_000,
        wrapped_blob=blob,
        label="Alice's share",
        owner_hint="ab12cd",
    )
    assert row_id > 0
    rows = state.list_held_shares()
    assert len(rows) == 1
    r = rows[0]
    assert r["share_index"] == 1
    assert r["threshold_k"] == 3
    assert r["total_n"] == 5
    assert r["setup_ms"] == 1_700_000_000_000
    assert r["wrapped_blob"] == blob
    assert r["label"] == "Alice's share"
    assert r["owner_hint"] == "ab12cd"


def test_insert_held_share_is_idempotent_on_blob(tmp_path):
    """Re-importing the same .olss file returns the same row id."""
    state = _open_state(tmp_path)
    blob = _make_wrapped_share()
    id_a = state.insert_held_share(
        share_index=1, threshold_k=3, total_n=5,
        setup_ms=1, wrapped_blob=blob,
    )
    id_b = state.insert_held_share(
        share_index=1, threshold_k=3, total_n=5,
        setup_ms=1, wrapped_blob=blob, label="(retry)",
    )
    assert id_a == id_b
    assert len(state.list_held_shares()) == 1


def test_delete_held_share_drops_row(tmp_path):
    state = _open_state(tmp_path)
    row_id = state.insert_held_share(
        share_index=1, threshold_k=3, total_n=5,
        setup_ms=1, wrapped_blob=_make_wrapped_share(),
    )
    assert state.delete_held_share(row_id) is True
    assert state.list_held_shares() == []
    # Second delete is a no-op.
    assert state.delete_held_share(row_id) is False


def test_get_held_share_returns_full_row(tmp_path):
    state = _open_state(tmp_path)
    blob = _make_wrapped_share()
    row_id = state.insert_held_share(
        share_index=2, threshold_k=2, total_n=3,
        setup_ms=42, wrapped_blob=blob,
        label="bob", owner_hint="ff00aa",
    )
    rec = state.get_held_share(row_id)
    assert rec is not None
    assert rec["id"] == row_id
    assert rec["share_index"] == 2
    assert rec["wrapped_blob"] == blob
    assert state.get_held_share(99999) is None


# ── recovery_api.parse_held_share_blob ──────────────────────────────


def test_parse_held_share_blob_extracts_metadata(tmp_path):
    from one_link import recovery_api
    blob = _make_wrapped_share(threshold_k=2, total_n=4)
    parsed = recovery_api.parse_held_share_blob(blob)
    assert parsed["share_index"] == 1
    assert parsed["threshold_k"] == 2
    assert parsed["total_n"] == 4
    assert parsed["wrapped_blob"] == blob


def test_parse_held_share_blob_rejects_bad_magic(tmp_path):
    from one_link import recovery_api
    with pytest.raises(ValueError):
        recovery_api.parse_held_share_blob(b"NOTOLSS" + os.urandom(80))


# ── HTTP endpoints ──────────────────────────────────────────────────


def test_held_shares_routes_registered_guarded():
    from one_link.server import UIServer
    daemon = SimpleNamespace(state=None, peer_rtc=None)
    server = UIServer(daemon)
    routes: dict[str, set[str]] = {}
    for resource in server.app.router.resources():
        info = resource.get_info()
        path = info.get("path") or info.get("formatter") or ""
        if "/recovery/shares" in path:
            for route in resource:
                routes.setdefault(path, set()).add(route.method)
    assert "POST" in routes.get("/api/v1/recovery/shares/import", set())
    assert "GET" in routes.get("/api/v1/recovery/shares", set())
    # The DELETE route uses a path-template parameter.
    delete_paths = [p for p in routes if p.startswith("/api/v1/recovery/shares/")
                    and "{share_id}" in p]
    assert delete_paths, f"DELETE route missing; routes={sorted(routes)}"
    assert "DELETE" in routes[delete_paths[0]]

    src = _server_src()
    for path_marker in (
        '"/api/v1/recovery/shares/import"',
        '"/api/v1/recovery/shares"',
        '"/api/v1/recovery/shares/{share_id}"',
    ):
        idx = src.find(path_marker)
        assert idx > 0, f"{path_marker} not registered"
        line_start = src.rfind("\n", 0, idx) + 1
        line_end = src.find("\n", idx)
        assert "self._guarded(" in src[line_start:line_end]


def test_held_shares_import_handler_caps_payload_and_validates_b64():
    """The handler caps blob_b64 at 3 KiB (.olss files are ~150B; the
    cap stops a hostile UI from triggering memory pressure) AND
    validates base64 before parsing."""
    src = _server_src()
    idx = src.find("async def api_recovery_shares_import(")
    assert idx > 0
    body = src[idx:idx + 3500]
    assert "len(blob_b64) > 4096" in body
    assert "validate=True" in body
    assert "parse_held_share_blob" in body
    assert "insert_held_share" in body
    assert "_recovery_no_store_headers" in body


# ── UI wiring ───────────────────────────────────────────────────────


def test_index_html_held_shares_api_methods_exist():
    html = _index_html()
    assert "recoveryHeldSharesList()" in html
    assert "recoveryHeldSharesImport(blobB64, label, ownerHint)" in html
    assert "recoveryHeldSharesDelete(shareId)" in html
    assert '"/api/v1/recovery/shares"' in html


# ── ship 2: unwrap endpoint ─────────────────────────────────────────


def test_unwrap_endpoint_registered_guarded_ratelimited():
    from one_link.server import UIServer
    daemon = SimpleNamespace(state=None, peer_rtc=None)
    server = UIServer(daemon)
    methods: set[str] = set()
    for resource in server.app.router.resources():
        info = resource.get_info()
        path = info.get("path") or info.get("formatter") or ""
        if path == "/api/v1/recovery/shares/{share_id}/unwrap":
            for route in resource:
                methods.add(route.method)
    assert "POST" in methods

    src = _server_src()
    idx = src.find('"/api/v1/recovery/shares/{share_id}/unwrap"')
    assert idx > 0
    line_start = src.rfind("\n", 0, idx) + 1
    line_end = src.find("\n", idx)
    assert "self._guarded(" in src[line_start:line_end]

    handler_idx = src.find("async def api_recovery_shares_unwrap(")
    assert handler_idx > 0
    body = src[handler_idx:handler_idx + 4000]
    assert "_rate_limited(" in body
    assert '"recovery_shares_unwrap"' in body
    assert "social_recovery.unwrap_share" in body
    assert "_recovery_no_store_headers" in body
    # Wipes the local seed copy after unwrap.
    assert 'b"\\x00" * len(my_seed)' in body


def test_unwrap_endpoint_returns_unwrapped_share_via_handler(tmp_path):
    """End-to-end: insert a real wrapped share into state, call the
    handler with a daemon stub whose identity priv matches the
    guardian pubkey used at wrap time, get back the same
    (idx, share_bytes) that wrap+combine would produce."""
    import asyncio
    from one_link import social_recovery
    from one_link.daemon import Daemon
    from one_link.state import State

    # Wrap a real share to a specific guardian keypair.
    guardian_priv = Ed25519PrivateKey.generate()
    guardian_pub = guardian_priv.public_key().public_bytes_raw()
    seed = os.urandom(32)
    shares = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=[guardian_pub, os.urandom(32) and Ed25519PrivateKey.generate().public_key().public_bytes_raw(), Ed25519PrivateKey.generate().public_key().public_bytes_raw()],
        threshold_k=2,
        total_n=3,
    )
    state = State(tmp_path / "r.db")
    row_id = state.insert_held_share(
        share_index=shares[0].share_index,
        threshold_k=shares[0].threshold,
        total_n=shares[0].total,
        setup_ms=shares[0].setup_ms,
        wrapped_blob=shares[0].encoded,
    )

    # Build a Daemon stub with the guardian identity in self.me.
    daemon = Daemon.__new__(Daemon)
    daemon.state = state

    class _Me:
        def __init__(self, priv):
            self.private = priv
            self.public_bytes = priv.public_key().public_bytes_raw()
    daemon.me = _Me(guardian_priv)

    # Build a minimal request stub for the aiohttp handler.
    class _Request:
        match_info = {"share_id": str(row_id)}
        transport = None
        @property
        def remote(self): return "127.0.0.1"
        headers = {}

    # The handler uses self._rate_limited which lives on UIServer,
    # so drive via the real UIServer.
    from one_link.server import UIServer
    srv = UIServer(daemon)
    res = asyncio.run(srv.api_recovery_shares_unwrap(_Request()))
    # The handler returns aiohttp web.Response. Parse the JSON body.
    import json as _json
    body = _json.loads(res.text)
    assert body["ok"] is True
    assert body["share_index"] == shares[0].share_index
    decoded = base64.b64decode(body["share_bytes_b64"])
    # Cross-check: the same unwrap done locally yields the same bytes.
    expected_idx, expected_bytes = social_recovery.unwrap_share(
        wrapped=shares[0].encoded,
        my_ed_priv_seed=guardian_priv.private_bytes_raw(),
    )
    assert body["share_index"] == expected_idx
    assert decoded == expected_bytes


def test_unwrap_endpoint_404s_on_unknown_share_id(tmp_path):
    import asyncio
    from one_link.daemon import Daemon
    from one_link.state import State
    state = State(tmp_path / "r.db")
    daemon = Daemon.__new__(Daemon)
    daemon.state = state

    class _Me:
        private = Ed25519PrivateKey.generate()
        public_bytes = private.public_key().public_bytes_raw()
    daemon.me = _Me()

    class _Request:
        match_info = {"share_id": "99999"}
        transport = None
        @property
        def remote(self): return "127.0.0.1"
        headers = {}

    from one_link.server import UIServer
    srv = UIServer(daemon)
    res = asyncio.run(srv.api_recovery_shares_unwrap(_Request()))
    assert res.status == 404


def test_index_html_unwrap_button_and_modal():
    """Each held-share row has an Unwrap button + the modal exists
    + shows the share bytes in a copy-able textarea + warns about
    treating bytes as sensitive material."""
    html = _index_html()
    assert 'recoveryHeldSharesUnwrap(shareId)' in html
    assert 'data-recwiz-share-unwrap' in html
    assert "async function _recwizHeldShareUnwrap(" in html
    idx = html.find("async function _recwizHeldShareUnwrap(")
    body = html[idx:idx + 4000]
    assert "api.recoveryHeldSharesUnwrap" in body
    assert "share_bytes_b64" in body
    assert "navigator.clipboard.writeText" in body
    # Warns the user that the unwrapped bytes are sensitive.
    assert "recwiz-warn" in body


# ── ship 3: recoverer-side combine ──────────────────────────────────


def test_restore_from_shares_round_trips_through_unwrap(tmp_path):
    """End-to-end of the third restore path: split seed into N
    shares, unwrap K of them, combine via recovery_api.restore_from_shares,
    confirm the on-disk seed matches the original."""
    from one_link import master_seed, recovery_api, social_recovery
    seed_in = os.urandom(32)
    guardians = [Ed25519PrivateKey.generate() for _ in range(5)]
    wrapped = social_recovery.split_and_wrap(
        seed=seed_in,
        contact_ed_pubs=[g.public_key().public_bytes_raw() for g in guardians],
        threshold_k=3,
        total_n=5,
    )
    # Unwrap 3 of 5 (the threshold).
    unwrapped: list[tuple[int, bytes]] = []
    for w, g in list(zip(wrapped, guardians))[:3]:
        idx, share_bytes = social_recovery.unwrap_share(
            wrapped=w.encoded, my_ed_priv_seed=g.private_bytes_raw(),
        )
        unwrapped.append((idx, share_bytes))

    # No existing seed on this install.
    assert not master_seed.has_seed(tmp_path)
    seed_out = recovery_api.restore_from_shares(
        data_dir=tmp_path,
        shares=unwrapped,
        delete_identity_files=False,
    )
    assert seed_out == seed_in
    assert master_seed.has_seed(tmp_path)
    assert master_seed.load_seed(tmp_path) == seed_in
    # The identity derived from the restored seed must match the
    # one the original install would have had.
    restored_pub = master_seed.derive_identity_priv(seed_in)\
        .public_key().public_bytes_raw()
    on_disk_pub = master_seed.derive_identity_priv(master_seed.load_seed(tmp_path))\
        .public_key().public_bytes_raw()
    assert restored_pub == on_disk_pub


def test_restore_from_shares_requires_threshold(tmp_path):
    """Below-threshold combine fails with ValueError; the daemon
    surfaces this as a 400 in the HTTP handler."""
    from one_link import recovery_api, social_recovery
    seed = os.urandom(32)
    guardians = [Ed25519PrivateKey.generate() for _ in range(5)]
    wrapped = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=[g.public_key().public_bytes_raw() for g in guardians],
        threshold_k=3,
        total_n=5,
    )
    # Only one share - well below threshold.
    one_unwrapped = social_recovery.unwrap_share(
        wrapped=wrapped[0].encoded,
        my_ed_priv_seed=guardians[0].private_bytes_raw(),
    )
    with pytest.raises(ValueError):
        recovery_api.restore_from_shares(
            data_dir=tmp_path,
            shares=[one_unwrapped],
            delete_identity_files=False,
        )


def test_restore_shares_endpoint_registered_guarded_ratelimited():
    from one_link.server import UIServer
    daemon = SimpleNamespace(state=None, peer_rtc=None)
    server = UIServer(daemon)
    methods: set[str] = set()
    for resource in server.app.router.resources():
        info = resource.get_info()
        path = info.get("path") or info.get("formatter") or ""
        if path == "/api/v1/recovery/restore/shares":
            for route in resource:
                methods.add(route.method)
    assert "POST" in methods
    src = _server_src()
    idx = src.find('"/api/v1/recovery/restore/shares"')
    assert idx > 0
    line_start = src.rfind("\n", 0, idx) + 1
    line_end = src.find("\n", idx)
    assert "self._guarded(" in src[line_start:line_end]
    handler_idx = src.find("async def api_recovery_restore_shares(")
    assert handler_idx > 0
    # The whole handler, however long it grows: up to the next method.
    handler_end = src.find("\n    async def ", handler_idx + 1)
    body = src[handler_idx:handler_end if handler_end > 0 else None]
    assert "_rate_limited(" in body
    assert '"recovery_restore_shares"' in body
    assert "destructive_restore_requires_confirmation" in body
    assert "share_lines" in body
    assert "_recovery_no_store_headers" in body


def test_index_html_shares_restore_in_modal():
    """The restore modal has a 'restore from shares' swap link AND
    a renderer that paste-textarea-collects + posts to the new
    endpoint AND a success card with the shutdown button."""
    html = _index_html()
    assert "recoveryRestoreShares(shareLines, force, confirmedReplace)" in html
    assert '"/api/v1/recovery/restore/shares"' in html
    assert "async function _renderRecoveryRestoreShares()" in html
    assert 'data-recwiz-restore-mode="shares"' in html
    assert 'data-recwiz-restore-mode="phrase"' in html
    idx = html.find("async function _renderRecoveryRestoreShares()")
    body = html[idx:idx + 6000]
    assert "api.recoveryRestoreShares" in body
    # Success card prompts restart + offers in-app shutdown.
    assert "recwiz-restart-card" in body
    assert "shares_restart" in body


def test_index_html_held_shares_card_in_wizard():
    html = _index_html()
    assert 'id="recwiz-track-held-shares"' in html
    assert 'data-track="held-shares"' in html
    assert "_recwizRenderHeldSharesCard" in html
    # Card has the import button + plain-English help disclosure.
    idx = html.find("async function _recwizRenderHeldSharesCard()")
    assert idx > 0
    body = html[idx:idx + 5000]
    assert 'data-recwiz-held="import"' in body
    assert "<summary>How does this work?</summary>" in body
    # Drop button uses native confirm before the destructive call.
    drop_idx = html.find("async function _recwizHeldShareDrop(")
    assert drop_idx > 0
    drop_body = html[drop_idx:drop_idx + 1000]
    assert "window.confirm" in drop_body
    assert "recoveryHeldSharesDelete" in drop_body
