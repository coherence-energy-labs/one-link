"""Full-duplex bidirectional folder sync over a SINGLE connection.

2026-05-27. The marquee proof that push_folder_to_peer(bidirectional=
True) exchanges blobs in BOTH directions within one dial/handshake/
ratchet cycle:

  - forward-only : A has a file, B doesn't  → B receives it
  - reverse-only : B has a file, A doesn't  → A receives it
  - both-at-once : A and B each have a DIFFERENT file in the same
                   shared folder → after ONE sync, each holds both
                   files byte-identical

The both-at-once case is the whole point: it cannot pass unless the
initiator's loop is truly full-duplex (serves its blobs AND receives
the peer's reverse manifest + blobs on the same channel).

Pairs via API (not mDNS), so it's deterministic on Windows.
"""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import aiohttp
import blake3
import pytest

from tests.harness import daemon_pair

pytestmark = pytest.mark.timeout(180)


def _read(home: Path, name: str) -> str:
    return (home / "data" / name).read_text(encoding="utf-8").strip()


async def _pair(s, base_a, tok_a, base_b, tok_b, p):
    async with s.get(f"{base_a}/api/peers?include_unpaired=1",
                     headers={"Authorization": f"Bearer {tok_a}"}) as r:
        ja = await r.json()
    fp_b = next((pp["fingerprint"] for pp in ja["peers"]
                 if pp["short_id"] == p.b.short_id), None)
    async with s.get(f"{base_b}/api/peers?include_unpaired=1",
                     headers={"Authorization": f"Bearer {tok_b}"}) as r:
        jb = await r.json()
    fp_a = next((pp["fingerprint"] for pp in jb["peers"]
                 if pp["short_id"] == p.a.short_id), None)
    assert fp_a and fp_b
    async with s.post(f"{base_a}/api/peers/{fp_b}/pair",
                      headers={"Authorization": f"Bearer {tok_a}"}, json={}) as r:
        assert (await r.json())["ok"]
    await asyncio.sleep(0.4)
    async with s.post(f"{base_a}/api/peers/{fp_b}/pair-confirm",
                      headers={"Authorization": f"Bearer {tok_a}"}, json={}) as r:
        assert (await r.json())["ok"]
    async with s.post(f"{base_b}/api/peers/{fp_a}/pair-confirm",
                      headers={"Authorization": f"Bearer {tok_b}"}, json={}) as r:
        assert (await r.json())["ok"]
    deadline = time.time() + 8
    while time.time() < deadline:
        async with s.get(f"{base_a}/api/peers",
                         headers={"Authorization": f"Bearer {tok_a}"}) as r:
            ja2 = await r.json()
        async with s.get(f"{base_b}/api/peers",
                         headers={"Authorization": f"Bearer {tok_b}"}) as r:
            jb2 = await r.json()
        av = next((pp for pp in ja2["peers"] if pp["fingerprint"] == fp_b), None)
        bv = next((pp for pp in jb2["peers"] if pp["fingerprint"] == fp_a), None)
        if av and bv and av["trust"] == "pinned" and bv["trust"] == "pinned":
            return fp_a, fp_b
        await asyncio.sleep(0.2)
    raise RuntimeError("pairing did not pin")


async def _mk_folder(s, base, tok, name, path, shared_with):
    path.mkdir(parents=True, exist_ok=True)
    async with s.post(f"{base}/api/folders",
                      headers={"Authorization": f"Bearer {tok}"},
                      json={"name": name, "local_path": str(path),
                            "shared_with": shared_with}) as r:
        assert r.status == 200, await r.text()


async def _sync(s, base, tok, name):
    async with s.post(f"{base}/api/folders/{name}/sync",
                      headers={"Authorization": f"Bearer {tok}"}, json={}) as r:
        return await r.json()


def _assert_hex64(value: object, *, field: str) -> str:
    assert isinstance(value, str), f"{field} is not a string: {value!r}"
    assert len(value) == 64, f"{field} is not 64 hex chars: {value!r}"
    assert value == value.lower(), f"{field} is not canonical lowercase hex"
    int(value, 16)
    return value


def _assert_durable_sync_receipt(
    response: dict,
    *,
    expected_entries: int,
    expected_wants: int,
) -> dict:
    """Validate the sender's exact, channel-bound folder commit proof.

    These tests disable only scheduled folder pushes and wait for the exact
    initial manifests. Both counts must therefore be exact: the explicit sync
    is the only delivery path, and an earlier background convergence cannot
    satisfy the test's single-connection claim.
    """
    assert response.get("ok") is True, response
    results = response.get("results")
    assert isinstance(results, list) and len(results) == 1, response
    result = results[0]
    assert result.get("status") == "pushed", result
    assert result.get("ok") is True, result
    assert result.get("durable_receipt") is True, result
    wants = result.get("wants")
    assert wants == expected_wants, result

    sync_id = result.get("folder_sync_id")
    assert isinstance(sync_id, str) and sync_id, result
    receipt = result.get("folder_sync_receipt")
    assert isinstance(receipt, dict), result
    assert receipt.get("v") == 1, receipt
    assert receipt.get("sync_id") == sync_id, receipt
    assert isinstance(receipt.get("verify_id"), str) and receipt["verify_id"]
    assert receipt.get("entry_count") == expected_entries, receipt
    # The receipt must agree with the live result about how many blobs the
    # receiver still wanted on this exact channel.
    assert receipt.get("wanted_count") == wants, receipt
    assert receipt.get("paths_verified") == expected_entries, receipt
    assert receipt.get("source_root") == result.get("merkle_root"), receipt
    _assert_hex64(receipt.get("source_root"), field="source_root")
    _assert_hex64(receipt.get("applied_root"), field="applied_root")
    _assert_hex64(receipt.get("manifest_digest"), field="manifest_digest")
    _assert_hex64(
        receipt.get("channel_transcript"), field="channel_transcript",
    )
    return result


async def _assert_exact_folder_state(
    s: aiohttp.ClientSession,
    *,
    base: str,
    token: str,
    home: Path,
    folder: str,
    local_root: Path,
    expected: dict[str, bytes],
) -> None:
    """Prove disk bytes, manifest rows, state blob index, and CAS agree."""
    async with s.get(
        f"{base}/api/folders/{folder}/tree",
        headers={"Authorization": f"Bearer {token}"},
    ) as response:
        body = await response.json()
        assert response.status == 200, body

    entries = body.get("entries")
    assert isinstance(entries, list), body
    by_path = {entry["path"]: entry for entry in entries}
    assert set(by_path) == set(expected), body
    assert body.get("truncated") is False, body
    expected_total = sum(len(payload) for payload in expected.values())
    assert body.get("total_bytes") == expected_total, body
    assert body.get("local_bytes") == expected_total, body

    for rel_path, payload in expected.items():
        digest = blake3.blake3(payload).hexdigest()
        entry = by_path[rel_path]
        assert entry.get("blob_hash") == digest, entry
        assert entry.get("size") == len(payload), entry
        assert entry.get("local") is True, entry
        assert (local_root / rel_path).read_bytes() == payload
        cas_path = home / "data" / "blobs" / digest[:2] / digest[2:]
        assert cas_path.is_file(), f"missing CAS object {digest}"
        assert cas_path.read_bytes() == payload


async def _wait_for_exact_folder_state(s: aiohttp.ClientSession, **kwargs) -> None:
    """Wait for watcher/initial-scan ingestion, proving the starting manifest."""
    deadline = time.monotonic() + 15.0
    while True:
        try:
            await _assert_exact_folder_state(s, **kwargs)
            return
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
            await asyncio.sleep(0.05)


async def _wait_file(path: Path, payload: bytes, timeout=30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.is_file() and path.read_bytes() == payload:
            return True
        await asyncio.sleep(0.4)
    return path.is_file() and path.read_bytes() == payload


@pytest.mark.live_daemon
@pytest.mark.asyncio
async def test_full_duplex_both_directions_one_connection():
    """A and B each drop a DIFFERENT file into the same shared folder.
    A single bidirectional sync from A must leave BOTH sides holding
    BOTH files — proving the initiator served its blob AND pulled the
    peer's blob on one channel."""
    with daemon_pair(pin_trust=True, periodic_folder_sync=False) as p:
        tok_a = _read(p.a.home, "ui.token")
        tok_b = _read(p.b.home, "ui.token")
        base_a = f"http://127.0.0.1:{int(_read(p.a.home, 'server.port'))}"
        base_b = f"http://127.0.0.1:{int(_read(p.b.home, 'server.port'))}"
        async with aiohttp.ClientSession() as s:
            fp_a, fp_b = await _pair(s, base_a, tok_a, base_b, tok_b, p)
            local_a = p.tmp / "fd_a"
            local_b = p.tmp / "fd_b"
            await _mk_folder(s, base_a, tok_a, "fd", local_a, [fp_b])
            await _mk_folder(s, base_b, tok_b, "fd", local_b, [fp_a])

            # Each side has a distinct file.
            pay_a = os.urandom(40_000)
            pay_b = os.urandom(55_000)
            (local_a / "from_a.bin").write_bytes(pay_a)
            (local_b / "from_b.bin").write_bytes(pay_b)
            await _wait_for_exact_folder_state(
                s, base=base_a, token=tok_a, home=p.a.home, folder="fd",
                local_root=local_a, expected={"from_a.bin": pay_a},
            )
            await _wait_for_exact_folder_state(
                s, base=base_b, token=tok_b, home=p.b.home, folder="fd",
                local_root=local_b, expected={"from_b.bin": pay_b},
            )

            # ONE bidirectional sync initiated by A.
            res = await _sync(s, base_a, tok_a, "fd")
            _assert_durable_sync_receipt(
                res, expected_entries=1, expected_wants=1,
            )

            # B must receive A's file AND A must receive B's file.
            got_b = await _wait_file(local_b / "from_a.bin", pay_a, timeout=30)
            got_a = await _wait_file(local_a / "from_b.bin", pay_b, timeout=30)
            if not (got_a and got_b):
                _d = Path(__file__).resolve().parents[1]
                (_d / "_fd_a.log").write_text(
                    p.a.log.read_text(encoding="utf-8", errors="replace"),
                    encoding="utf-8")
                (_d / "_fd_b.log").write_text(
                    p.b.log.read_text(encoding="utf-8", errors="replace"),
                    encoding="utf-8")
            assert got_b, "B did not receive A's file (forward direction)"
            assert got_a, (
                "A did not receive B's file (REVERSE direction) — "
                "full-duplex single-connection sync is broken"
            )
            expected = {"from_a.bin": pay_a, "from_b.bin": pay_b}
            await _assert_exact_folder_state(
                s,
                base=base_a,
                token=tok_a,
                home=p.a.home,
                folder="fd",
                local_root=local_a,
                expected=expected,
            )
            await _assert_exact_folder_state(
                s,
                base=base_b,
                token=tok_b,
                home=p.b.home,
                folder="fd",
                local_root=local_b,
                expected=expected,
            )


@pytest.mark.live_daemon
@pytest.mark.asyncio
async def test_full_duplex_forward_only():
    """Only A has a file. One bidirectional sync delivers it to B
    (degrades gracefully to the forward direction)."""
    with daemon_pair(pin_trust=True, periodic_folder_sync=False) as p:
        tok_a = _read(p.a.home, "ui.token")
        tok_b = _read(p.b.home, "ui.token")
        base_a = f"http://127.0.0.1:{int(_read(p.a.home, 'server.port'))}"
        base_b = f"http://127.0.0.1:{int(_read(p.b.home, 'server.port'))}"
        async with aiohttp.ClientSession() as s:
            fp_a, fp_b = await _pair(s, base_a, tok_a, base_b, tok_b, p)
            local_a = p.tmp / "fo_a"
            local_b = p.tmp / "fo_b"
            await _mk_folder(s, base_a, tok_a, "fo", local_a, [fp_b])
            await _mk_folder(s, base_b, tok_b, "fo", local_b, [fp_a])
            pay = os.urandom(30_000)
            (local_a / "only.bin").write_bytes(pay)
            await _wait_for_exact_folder_state(
                s, base=base_a, token=tok_a, home=p.a.home, folder="fo",
                local_root=local_a, expected={"only.bin": pay},
            )
            await _wait_for_exact_folder_state(
                s, base=base_b, token=tok_b, home=p.b.home, folder="fo",
                local_root=local_b, expected={},
            )
            res = await _sync(s, base_a, tok_a, "fo")
            _assert_durable_sync_receipt(
                res, expected_entries=1, expected_wants=1,
            )
            assert await _wait_file(local_b / "only.bin", pay, timeout=30)
            expected = {"only.bin": pay}
            await _assert_exact_folder_state(
                s,
                base=base_a,
                token=tok_a,
                home=p.a.home,
                folder="fo",
                local_root=local_a,
                expected=expected,
            )
            await _assert_exact_folder_state(
                s,
                base=base_b,
                token=tok_b,
                home=p.b.home,
                folder="fo",
                local_root=local_b,
                expected=expected,
            )


@pytest.mark.live_daemon
@pytest.mark.asyncio
async def test_full_duplex_reverse_only():
    """Only B has a file. A initiates a bidirectional sync; the file
    flows in the REVERSE direction (B → A) on the same connection."""
    with daemon_pair(pin_trust=True, periodic_folder_sync=False) as p:
        tok_a = _read(p.a.home, "ui.token")
        tok_b = _read(p.b.home, "ui.token")
        base_a = f"http://127.0.0.1:{int(_read(p.a.home, 'server.port'))}"
        base_b = f"http://127.0.0.1:{int(_read(p.b.home, 'server.port'))}"
        async with aiohttp.ClientSession() as s:
            fp_a, fp_b = await _pair(s, base_a, tok_a, base_b, tok_b, p)
            local_a = p.tmp / "ro_a"
            local_b = p.tmp / "ro_b"
            await _mk_folder(s, base_a, tok_a, "ro", local_a, [fp_b])
            await _mk_folder(s, base_b, tok_b, "ro", local_b, [fp_a])
            pay = os.urandom(35_000)
            (local_b / "rev.bin").write_bytes(pay)
            await _wait_for_exact_folder_state(
                s, base=base_a, token=tok_a, home=p.a.home, folder="ro",
                local_root=local_a, expected={},
            )
            await _wait_for_exact_folder_state(
                s, base=base_b, token=tok_b, home=p.b.home, folder="ro",
                local_root=local_b, expected={"rev.bin": pay},
            )
            # A initiates (A has nothing) — file must still arrive at A.
            res = await _sync(s, base_a, tok_a, "ro")
            _assert_durable_sync_receipt(
                res, expected_entries=0, expected_wants=0,
            )
            assert await _wait_file(local_a / "rev.bin", pay, timeout=30), (
                "A did not receive B's file via the reverse direction "
                "of a bidirectional sync A initiated"
            )
            expected = {"rev.bin": pay}
            await _assert_exact_folder_state(
                s,
                base=base_a,
                token=tok_a,
                home=p.a.home,
                folder="ro",
                local_root=local_a,
                expected=expected,
            )
            await _assert_exact_folder_state(
                s,
                base=base_b,
                token=tok_b,
                home=p.b.home,
                folder="ro",
                local_root=local_b,
                expected=expected,
            )
