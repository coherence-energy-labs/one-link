"""v0.21.x two-daemon end-to-end folder send.

Real wire test: spawns two daemons via the harness, pairs them,
creates a folder on A with real files, calls /api/folders/{name}/
send-to on A targeting B, waits for the files to land in B's
inbox or accepted folder location.

This catches the class of bugs unit tests with FakeChannel can't:
  - Wire format mismatches (MANIFEST_PUSH / MANIFEST_WANTS /
    BLOB_OFFER / BLOB_CHUNK frame field shape changes)
  - Capability negotiation regressions
  - mDNS discovery + dial path
  - Real receiver Accept-then-pull flow
  - Compression negotiation (FILE_COMPRESSION cap honoured)

Slow test (~30s on a quiet laptop) — gated behind ``-m e2e`` so the
unit suite stays fast.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

import aiohttp
import blake3
import pytest

from tests.harness import daemon_pair


def _read_tok_and_port(home: Path) -> tuple[str, int]:
    tok = (home / "data" / "ui.token").read_text().strip()
    port = int((home / "data" / "server.port").read_text().strip())
    return tok, port


def _assert_hex64(value: object, *, field: str) -> str:
    assert isinstance(value, str), f"{field} is not a string: {value!r}"
    assert len(value) == 64, f"{field} is not 64 hex chars: {value!r}"
    assert value == value.lower(), f"{field} is not canonical lowercase hex"
    int(value, 16)
    return value


async def _wait_for_durable_sender_completion(
    s: aiohttp.ClientSession,
    *,
    base: str,
    token: str,
    peer_fp: str,
    expected_entries: int,
) -> dict:
    """Wait until the one-shot follow-up has an exact durable receipt."""
    deadline = time.time() + 10
    transfers: list[dict] = []
    completed = None
    while time.time() < deadline:
        async with s.get(
            f"{base}/api/transfers?peer_fp={peer_fp}&limit=25",
            headers={"Authorization": f"Bearer {token}"},
        ) as response:
            body = await response.json()
            assert response.status == 200, body
        transfers = body.get("transfers") or []
        completed = next(
            (
                row for row in transfers
                if row.get("direction") == "out"
                and row.get("kind") == "folder"
                and row.get("name") == "demo_send"
                and row.get("status") == "complete"
                and (row.get("metadata") or {}).get("durable_receipt") is True
            ),
            None,
        )
        if completed is not None:
            break
        await asyncio.sleep(0.1)
    assert completed is not None, transfers

    metadata = completed.get("metadata") or {}
    sync_id = metadata.get("folder_sync_id")
    assert isinstance(sync_id, str) and sync_id, completed
    receipt = metadata.get("folder_sync_receipt")
    assert isinstance(receipt, dict), completed
    assert receipt.get("v") == 1, receipt
    assert receipt.get("sync_id") == sync_id, receipt
    assert isinstance(receipt.get("verify_id"), str) and receipt["verify_id"]
    assert receipt.get("entry_count") == expected_entries, receipt
    assert receipt.get("wanted_count") == expected_entries, receipt
    assert receipt.get("paths_verified") == expected_entries, receipt
    assert receipt.get("source_root") == metadata.get("merkle_root"), receipt
    assert receipt.get("applied_root") == metadata.get("merkle_root"), receipt
    assert completed.get("blob_hash") == metadata.get("merkle_root"), completed
    _assert_hex64(receipt.get("source_root"), field="source_root")
    _assert_hex64(receipt.get("applied_root"), field="applied_root")
    _assert_hex64(receipt.get("manifest_digest"), field="manifest_digest")
    _assert_hex64(
        receipt.get("channel_transcript"), field="channel_transcript",
    )
    return completed


async def _assert_receiver_state_and_cas(
    s: aiohttp.ClientSession,
    *,
    base: str,
    token: str,
    home: Path,
    target: Path,
    expected: dict[str, bytes],
) -> None:
    async with s.get(
        f"{base}/api/folders/demo_send/tree",
        headers={"Authorization": f"Bearer {token}"},
    ) as response:
        body = await response.json()
        assert response.status == 200, body
    entries = body.get("entries")
    assert isinstance(entries, list), body
    by_path = {entry["path"]: entry for entry in entries}
    assert set(by_path) == set(expected), body
    assert body.get("truncated") is False, body
    expected_bytes = sum(len(payload) for payload in expected.values())
    assert body.get("total_bytes") == expected_bytes, body
    assert body.get("local_bytes") == expected_bytes, body

    disk_files = {
        path.relative_to(target).as_posix()
        for path in target.rglob("*")
        if path.is_file()
    }
    assert disk_files == set(expected)
    for rel_path, payload in expected.items():
        digest = blake3.blake3(payload).hexdigest()
        entry = by_path[rel_path]
        assert entry.get("blob_hash") == digest, entry
        assert entry.get("size") == len(payload), entry
        assert entry.get("local") is True, entry
        assert (target / rel_path).read_bytes() == payload
        cas_path = home / "data" / "blobs" / digest[:2] / digest[2:]
        assert cas_path.is_file(), f"missing receiver CAS object {digest}"
        assert cas_path.read_bytes() == payload


async def _pair(p) -> tuple[str, str]:
    """Pair A + B; return (fp_a_seen_by_b, fp_b_seen_by_a)."""
    ta, port_a = _read_tok_and_port(p.a.home)
    tb, port_b = _read_tok_and_port(p.b.home)
    base_a = f"http://127.0.0.1:{port_a}"
    base_b = f"http://127.0.0.1:{port_b}"
    async with aiohttp.ClientSession() as s:
        async with s.get(
            f"{base_a}/api/peers?include_unpaired=1",
            headers={"Authorization": f"Bearer {ta}"},
        ) as r:
            jb = await r.json()
        fp_b = next(
            (pp["fingerprint"] for pp in jb["peers"]
             if pp["short_id"] == p.b.short_id),
            None,
        )
        assert fp_b, f"B short_id {p.b.short_id} not visible from A"
        async with s.get(
            f"{base_b}/api/peers?include_unpaired=1",
            headers={"Authorization": f"Bearer {tb}"},
        ) as r:
            ja = await r.json()
        fp_a = next(
            (pp["fingerprint"] for pp in ja["peers"]
             if pp["short_id"] == p.a.short_id),
            None,
        )
        assert fp_a, f"A short_id {p.a.short_id} not visible from B"
        # Pair initiate + confirm.
        async with s.post(
            f"{base_a}/api/peers/{fp_b}/pair",
            headers={"Authorization": f"Bearer {ta}"}, json={},
        ) as r:
            assert (await r.json())["ok"]
        await asyncio.sleep(0.5)
        async with s.post(
            f"{base_a}/api/peers/{fp_b}/pair-confirm",
            headers={"Authorization": f"Bearer {ta}"}, json={},
        ) as r:
            assert (await r.json())["ok"]
        async with s.post(
            f"{base_b}/api/peers/{fp_a}/pair-confirm",
            headers={"Authorization": f"Bearer {tb}"}, json={},
        ) as r:
            assert (await r.json())["ok"]
        deadline = time.time() + 8
        while time.time() < deadline:
            async with s.get(
                f"{base_a}/api/peers",
                headers={"Authorization": f"Bearer {ta}"},
            ) as r:
                ja2 = await r.json()
            async with s.get(
                f"{base_b}/api/peers",
                headers={"Authorization": f"Bearer {tb}"},
            ) as r:
                jb2 = await r.json()
            a_view = next(
                (pp for pp in ja2["peers"] if pp["fingerprint"] == fp_b),
                None,
            )
            b_view = next(
                (pp for pp in jb2["peers"] if pp["fingerprint"] == fp_a),
                None,
            )
            if (
                a_view and b_view
                and a_view["trust"] == "pinned"
                and b_view["trust"] == "pinned"
            ):
                return fp_a, fp_b
            await asyncio.sleep(0.25)
        pytest.fail("pair did not settle to mutual pinned within 8s")


@pytest.mark.live_daemon
@pytest.mark.asyncio
@pytest.mark.timeout(180)
async def test_folder_send_via_manifest_real_wire():
    """End-to-end: A creates a folder, sends to B via the default
    MANIFEST_PUSH ceremony. B should auto-create the folder (since
    paired but not yet shared) and pull the blobs."""
    with daemon_pair(pin_trust=True) as p:
        fp_a, fp_b = await _pair(p)
        ta, port_a = _read_tok_and_port(p.a.home)
        tb, port_b = _read_tok_and_port(p.b.home)
        base_a = f"http://127.0.0.1:{port_a}"
        base_b = f"http://127.0.0.1:{port_b}"
        # Build a folder on A.
        src = p.a.home / "to_send"
        src.mkdir()
        (src / "a.txt").write_text("alpha", encoding="utf-8")
        (src / "sub").mkdir()
        (src / "sub" / "b.txt").write_text("beta", encoding="utf-8")
        async with aiohttp.ClientSession() as s:
            # Register folder on A.
            async with s.post(
                f"{base_a}/api/folders",
                headers={"Authorization": f"Bearer {ta}"},
                json={
                    "name": "demo_send",
                    "local_path": str(src),
                    "shared_with": [],
                },
            ) as r:
                add_resp = await r.json()
                assert add_resp.get("ok"), f"add_folder failed: {add_resp}"
            # Wait for initial scan.
            await asyncio.sleep(1.0)
            # Trigger one-shot send to B via MANIFEST_PUSH ceremony.
            async with s.post(
                f"{base_a}/api/folders/demo_send/send-to",
                headers={"Authorization": f"Bearer {ta}"},
                json={"peer_fp": fp_b, "mode": "manifest_push"},
            ) as r:
                send_resp = await r.json()
                assert send_resp.get("ok"), f"send failed: {send_resp}"
                assert send_resp.get("mode") == "manifest_push"
            # B's receiver should see a folder offer card. With
            # self-mesh check returning False (these are two
            # distinct identities), the offer stays pending until
            # we accept.
            deadline = time.time() + 30
            offer = None
            while time.time() < deadline:
                async with s.get(
                    f"{base_b}/api/folder-offers",
                    headers={"Authorization": f"Bearer {tb}"},
                ) as r:
                    offers_resp = await r.json()
                offers = offers_resp.get("offers") or []
                offer = next(
                    (o for o in offers if o["folder_name"] == "demo_send"),
                    None,
                )
                if offer:
                    break
                await asyncio.sleep(0.5)
            assert offer is not None, "B never received the folder offer"
            # Accept the offer.
            target = p.b.home / "received_demo"
            async with s.post(
                f"{base_b}/api/folder-offers/{offer['id']}/accept",
                headers={"Authorization": f"Bearer {tb}"},
                json={"local_path": str(target)},
            ) as r:
                accept_resp = await r.json()
                assert accept_resp.get("ok"), (
                    f"accept failed: {accept_resp}"
                )
            # Wait for the files to land.
            deadline = time.time() + 30
            while time.time() < deadline:
                if (
                    (target / "a.txt").is_file()
                    and (target / "sub" / "b.txt").is_file()
                ):
                    break
                await asyncio.sleep(0.5)
            assert (target / "a.txt").is_file(), (
                "a.txt didn't land on B within 30s after Accept"
            )
            assert (target / "a.txt").read_text(encoding="utf-8") == "alpha"
            assert (target / "sub" / "b.txt").read_text(encoding="utf-8") == "beta", (
                "sub/b.txt content mismatch on B"
            )
            expected = {"a.txt": b"alpha", "sub/b.txt": b"beta"}
            await _assert_receiver_state_and_cas(
                s,
                base=base_b,
                token=tb,
                home=p.b.home,
                target=target,
                expected=expected,
            )
            await _wait_for_durable_sender_completion(
                s,
                base=base_a,
                token=ta,
                peer_fp=fp_b,
                expected_entries=len(expected),
            )
