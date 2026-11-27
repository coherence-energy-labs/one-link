"""End-to-end folder sync between two real daemons.

Spins up a daemon pair, pairs them via SAS so trust is 'pinned', creates
a folder on A, shares it with B, drops a file in A's folder, and verifies
B's copy receives the file byte-identical.

This is the marquee test for live folder sync: it proves
the folder-sync wire protocol actually moves bytes between peers.
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


def _assert_hex64(value: object, *, field: str) -> str:
    assert isinstance(value, str), f"{field} is not a string: {value!r}"
    assert len(value) == 64, f"{field} is not 64 hex chars: {value!r}"
    assert value == value.lower(), f"{field} is not canonical lowercase hex"
    int(value, 16)
    return value


def _assert_durable_sync_result(
    response: dict,
    *,
    expected_entries: int,
    expected_wants: int | frozenset[int],
) -> dict:
    """Validate the sender's durable, channel-bound sync result.

    ``expected_wants`` is a set where the count legitimately depends on timing:
    the folder watcher pushes a new file on its own, so by the time an explicit
    sync runs the receiver may already hold it (wants 0) or not (wants 1). The
    receipt must agree with the result either way.
    """
    allowed = {expected_wants} if isinstance(expected_wants, int) else set(expected_wants)
    assert response.get("ok") is True, response
    results = response.get("results")
    assert isinstance(results, list) and len(results) == 1, response
    result = results[0]
    assert result.get("status") == "pushed", result
    assert result.get("ok") is True, result
    assert result.get("durable_receipt") is True, result
    wants = result.get("wants")
    assert wants in allowed, result
    sync_id = result.get("folder_sync_id")
    assert isinstance(sync_id, str) and sync_id, result

    receipt = result.get("folder_sync_receipt")
    assert isinstance(receipt, dict), result
    assert receipt.get("v") == 1, receipt
    assert receipt.get("sync_id") == sync_id, receipt
    assert isinstance(receipt.get("verify_id"), str) and receipt["verify_id"]
    assert receipt.get("entry_count") == expected_entries, receipt
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


async def _assert_sender_ledger_receipt(
    s: aiohttp.ClientSession,
    *,
    base: str,
    token: str,
    peer_fp: str,
    result: dict,
) -> None:
    """Prove the sender persisted the same exact receipt in its ledger."""
    deadline = time.time() + 5
    matching = None
    transfers: list[dict] = []
    while time.time() < deadline:
        async with s.get(
            f"{base}/api/transfers?peer_fp={peer_fp}&limit=25",
            headers={"Authorization": f"Bearer {token}"},
        ) as response:
            body = await response.json()
            assert response.status == 200, body
        transfers = body.get("transfers") or []
        matching = next(
            (
                row for row in transfers
                if row.get("kind") == "folder"
                and row.get("name") == "shared"
                and (row.get("metadata") or {}).get("folder_sync_id")
                == result["folder_sync_id"]
            ),
            None,
        )
        if matching is not None and matching.get("status") == "complete":
            break
        await asyncio.sleep(0.1)
    assert matching is not None, transfers
    assert matching.get("status") == "complete", matching
    metadata = matching.get("metadata") or {}
    assert metadata.get("durable_receipt") is True, matching
    assert metadata.get("merkle_root") == result.get("merkle_root"), matching
    assert metadata.get("folder_sync_receipt") == result.get(
        "folder_sync_receipt",
    ), matching


async def _assert_receiver_state_and_cas(
    s: aiohttp.ClientSession,
    *,
    base: str,
    token: str,
    home: Path,
    local_root: Path,
    payload: bytes,
) -> None:
    digest = blake3.blake3(payload).hexdigest()
    async with s.get(
        f"{base}/api/folders/shared/tree",
        headers={"Authorization": f"Bearer {token}"},
    ) as response:
        body = await response.json()
        assert response.status == 200, body
    assert body.get("truncated") is False, body
    assert body.get("total_entries") == 1, body
    assert body.get("total_entries_available") == 1, body
    assert body.get("total_bytes") == len(payload), body
    assert body.get("local_bytes") == len(payload), body
    entry = (body.get("entries") or [None])[0]
    assert isinstance(entry, dict), body
    assert entry.get("path") == "hello.bin", entry
    assert entry.get("blob_hash") == digest, entry
    assert entry.get("size") == len(payload), entry
    assert entry.get("local") is True, entry
    assert (local_root / "hello.bin").read_bytes() == payload
    cas_path = home / "data" / "blobs" / digest[:2] / digest[2:]
    assert cas_path.is_file(), f"missing receiver CAS object {digest}"
    assert cas_path.read_bytes() == payload


async def _pair_two_daemons(s, base_a, tok_a, base_b, tok_b, p):
    """Drive the SAS pairing dance via API so both peers end up trust=pinned."""
    # Pre-pair lookups need ?include_unpaired=1 since the v0.4 default
    # /api/peers feed is paired-only (sidebar contract).
    async with s.get(
        f"{base_a}/api/peers?include_unpaired=1",
        headers={"Authorization": f"Bearer {tok_a}"},
    ) as r:
        ja = await r.json()
    fp_b = next(
        (pp["fingerprint"] for pp in ja["peers"] if pp["short_id"] == p.b.short_id),
        None,
    )
    assert fp_b, f"peer {p.b.short_id} not visible from A: {ja['peers']!r}"

    async with s.get(
        f"{base_b}/api/peers?include_unpaired=1",
        headers={"Authorization": f"Bearer {tok_b}"},
    ) as r:
        jb = await r.json()
    fp_a = next(
        (pp["fingerprint"] for pp in jb["peers"] if pp["short_id"] == p.a.short_id),
        None,
    )
    assert fp_a, f"peer {p.a.short_id} not visible from B: {jb['peers']!r}"

    # A initiates pair
    async with s.post(
        f"{base_a}/api/peers/{fp_b}/pair",
        headers={"Authorization": f"Bearer {tok_a}"}, json={},
    ) as r:
        assert (await r.json())["ok"]
    await asyncio.sleep(0.5)

    # Both confirm
    async with s.post(
        f"{base_a}/api/peers/{fp_b}/pair-confirm",
        headers={"Authorization": f"Bearer {tok_a}"}, json={},
    ) as r:
        assert (await r.json())["ok"]
    async with s.post(
        f"{base_b}/api/peers/{fp_a}/pair-confirm",
        headers={"Authorization": f"Bearer {tok_b}"}, json={},
    ) as r:
        assert (await r.json())["ok"]

    # Wait for both sides to be pinned. Default /api/peers (paired-only)
    # is appropriate here — once pinning lands, the peer must be visible
    # in the sidebar feed.
    deadline = time.time() + 8
    a_view = b_view = None
    while time.time() < deadline:
        async with s.get(f"{base_a}/api/peers", headers={"Authorization": f"Bearer {tok_a}"}) as r:
            ja2 = await r.json()
        async with s.get(f"{base_b}/api/peers", headers={"Authorization": f"Bearer {tok_b}"}) as r:
            jb2 = await r.json()
        a_view = next((pp for pp in ja2["peers"] if pp["fingerprint"] == fp_b), None)
        b_view = next((pp for pp in jb2["peers"] if pp["fingerprint"] == fp_a), None)
        if a_view and b_view and a_view["trust"] == "pinned" and b_view["trust"] == "pinned":
            return fp_a, fp_b
        await asyncio.sleep(0.2)
    raise RuntimeError(
        f"pairing did not pin: A={a_view and a_view.get('trust')} "
        f"B={b_view and b_view.get('trust')}"
    )


@pytest.mark.live_daemon
@pytest.mark.asyncio
async def test_folder_sync_round_trip():
    """A pairs with B, A creates a folder shared with B, A drops a file.
    B's copy of the folder receives the file byte-identical."""
    # No scheduled pushes: this test is about the explicit sync and the
    # watcher, and a background cycle landing in between proved nothing.
    with daemon_pair(pin_trust=True, periodic_folder_sync=False) as p:
        port_a = int(_read(p.a.home, "server.port"))
        port_b = int(_read(p.b.home, "server.port"))
        tok_a = _read(p.a.home, "ui.token")
        tok_b = _read(p.b.home, "ui.token")
        base_a = f"http://127.0.0.1:{port_a}"
        base_b = f"http://127.0.0.1:{port_b}"

        async with aiohttp.ClientSession() as s:
            fp_a, fp_b = await _pair_two_daemons(s, base_a, tok_a, base_b, tok_b, p)

            # Create the folder on A's side
            local_a = p.tmp / "shared_a"
            local_a.mkdir()
            local_b = p.tmp / "shared_b"
            local_b.mkdir()

            async with s.post(
                f"{base_a}/api/folders",
                headers={"Authorization": f"Bearer {tok_a}"},
                json={
                    "name": "shared", "local_path": str(local_a),
                    "shared_with": [fp_b],
                },
            ) as r:
                resp = await r.json()
            assert r.status == 200, resp

            # B opens the matching folder so it has a place to materialize
            async with s.post(
                f"{base_b}/api/folders",
                headers={"Authorization": f"Bearer {tok_b}"},
                json={
                    "name": "shared", "local_path": str(local_b),
                    "shared_with": [fp_a],
                },
            ) as r:
                resp = await r.json()
            assert r.status == 200, resp

            # Drop a file into A's folder
            payload = os.urandom(50_000)
            sample = local_a / "hello.bin"
            sample.write_bytes(payload)

            # Give the watcher a moment to ingest
            await asyncio.sleep(1.5)

            # Ask A to sync now (instead of waiting 30s)
            async with s.post(
                f"{base_a}/api/folders/shared/sync",
                headers={"Authorization": f"Bearer {tok_a}"}, json={},
            ) as r:
                sync_res = await r.json()
            # The watcher may have delivered the new file already. Asserting
            # wants == 1 here bet that it had not, and lost on a slow runner
            # (the result was a durable, verified push with wants == 0). What
            # must hold either way is asserted below: one verified entry, a
            # receipt that agrees with the result, the bytes on B, B's state
            # and store, and A's ledger.
            first_result = _assert_durable_sync_result(
                sync_res, expected_entries=1, expected_wants=frozenset({0, 1}),
            )

            # Wait for B to materialize the file
            target = local_b / "hello.bin"
            deadline = time.time() + 30
            while time.time() < deadline:
                if target.is_file() and target.read_bytes() == payload:
                    break
                await asyncio.sleep(0.4)
            else:
                a_log = p.a.log.read_text(encoding="utf-8", errors="replace")[-3000:]
                b_log = p.b.log.read_text(encoding="utf-8", errors="replace")[-3000:]
                pytest.fail(
                    f"file did not arrive at {target}\n"
                    f"--- A log ---\n{a_log}\n"
                    f"--- B log ---\n{b_log}\n"
                )
            assert target.read_bytes() == payload
            await _assert_receiver_state_and_cas(
                s,
                base=base_b,
                token=tok_b,
                home=p.b.home,
                local_root=local_b,
                payload=payload,
            )
            await _assert_sender_ledger_receipt(
                s,
                base=base_a,
                token=tok_a,
                peer_fp=fp_b,
                result=first_result,
            )

            async with s.post(
                f"{base_a}/api/folders/shared/sync",
                headers={"Authorization": f"Bearer {tok_a}"}, json={},
            ) as r:
                sync_res_2 = await r.json()
            second_result = _assert_durable_sync_result(
                sync_res_2, expected_entries=1, expected_wants=0,
            )
            assert second_result["merkle_root"] == first_result["merkle_root"]
            await _assert_receiver_state_and_cas(
                s,
                base=base_b,
                token=tok_b,
                home=p.b.home,
                local_root=local_b,
                payload=payload,
            )
            await _assert_sender_ledger_receipt(
                s,
                base=base_a,
                token=tok_a,
                peer_fp=fp_b,
                result=second_result,
            )


@pytest.mark.live_daemon
@pytest.mark.asyncio
async def test_folder_sync_blocked_for_unpaired_peer():
    """Without pairing, MANIFEST_PUSH should be ignored on the receive side
    and no file ever materializes — the trust gate works."""
    with daemon_pair() as p:
        port_a = int(_read(p.a.home, "server.port"))
        port_b = int(_read(p.b.home, "server.port"))
        tok_a = _read(p.a.home, "ui.token")
        tok_b = _read(p.b.home, "ui.token")
        base_a = f"http://127.0.0.1:{port_a}"
        base_b = f"http://127.0.0.1:{port_b}"

        async with aiohttp.ClientSession() as s:
            # Get fingerprints — peers are unpaired so use modal feed.
            async with s.get(
                f"{base_a}/api/peers?include_unpaired=1",
                headers={"Authorization": f"Bearer {tok_a}"},
            ) as r:
                ja = await r.json()
            fp_b = next(
                (pp["fingerprint"] for pp in ja["peers"] if pp["short_id"] == p.b.short_id),
                None,
            )
            assert fp_b, f"peer {p.b.short_id} not visible from A"
            async with s.get(
                f"{base_b}/api/peers?include_unpaired=1",
                headers={"Authorization": f"Bearer {tok_b}"},
            ) as r:
                jb = await r.json()
            fp_a = next(
                (pp["fingerprint"] for pp in jb["peers"] if pp["short_id"] == p.a.short_id),
                None,
            )
            assert fp_a, f"peer {p.a.short_id} not visible from B"

            # NO pairing — peers are 'pending'
            local_a = p.tmp / "shared_a"
            local_a.mkdir()
            local_b = p.tmp / "shared_b"
            local_b.mkdir()

            async with s.post(
                f"{base_a}/api/folders",
                headers={"Authorization": f"Bearer {tok_a}"},
                json={"name": "shared", "local_path": str(local_a), "shared_with": [fp_b]},
            ) as r:
                assert r.status == 200, await r.text()
            async with s.post(
                f"{base_b}/api/folders",
                headers={"Authorization": f"Bearer {tok_b}"},
                json={"name": "shared", "local_path": str(local_b), "shared_with": [fp_a]},
            ) as r:
                assert r.status == 200, await r.text()

            (local_a / "secret.bin").write_bytes(b"do not sync me")
            await asyncio.sleep(1.5)
            async with s.post(
                f"{base_a}/api/folders/shared/sync",
                headers={"Authorization": f"Bearer {tok_a}"}, json={},
            ) as r:
                res = await r.json()
            # Push should report not_pinned
            blocked_results = res.get("results", [])
            statuses = [r["status"] for r in blocked_results]
            assert "not_pinned" in statuses
            blocked = next(r for r in blocked_results if r["status"] == "not_pinned")
            assert blocked.get("ok") is False, blocked
            assert "durable_receipt" not in blocked, blocked
            assert "folder_sync_receipt" not in blocked, blocked

            # And the file does NOT show up on B
            await asyncio.sleep(1.5)
            assert not (local_b / "secret.bin").exists()
            async with s.get(
                f"{base_b}/api/folders/shared/tree",
                headers={"Authorization": f"Bearer {tok_b}"},
            ) as r:
                receiver_tree = await r.json()
                assert r.status == 200, receiver_tree
            assert receiver_tree.get("entries") == [], receiver_tree
            secret_hash = blake3.blake3(b"do not sync me").hexdigest()
            receiver_cas = (
                p.b.home / "data" / "blobs"
                / secret_hash[:2] / secret_hash[2:]
            )
            assert not receiver_cas.exists()
