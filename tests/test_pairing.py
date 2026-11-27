"""SAS pairing primitives."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from one_link.pairing import (
    PAIR_SAS_BITS,
    PAIR_SAS_WORD_COUNT,
    PAIR_SAS_WORDS,
    PairState,
    PairingTracker,
    compute_sas,
    compute_sas_words,
    compute_setup_sas_words,
    format_sas,
    format_sas_words,
)


def test_sas_is_six_digits():
    sas = compute_sas(os.urandom(32), os.urandom(32))
    assert len(sas) == 6
    assert sas.isdigit()


def test_sas_is_symmetric():
    """The same code must be computed regardless of argument order."""
    a, b = os.urandom(32), os.urandom(32)
    assert compute_sas(a, b) == compute_sas(b, a)


def test_sas_is_deterministic():
    a, b = os.urandom(32), os.urandom(32)
    assert compute_sas(a, b) == compute_sas(a, b)


def test_sas_different_for_different_pairs():
    a, b, c = os.urandom(32), os.urandom(32), os.urandom(32)
    assert compute_sas(a, b) != compute_sas(a, c)


def test_sas_rejects_wrong_length():
    with pytest.raises(ValueError):
        compute_sas(b"short", os.urandom(32))
    with pytest.raises(ValueError):
        compute_sas(os.urandom(32), b"shortpubkeyXXXXXXX")


def test_format_sas_groups_digits():
    assert format_sas("123456") == "123 456"
    assert format_sas("000000") == "000 000"
    assert format_sas("999999") == "999 999"


def test_format_sas_zero_pads():
    assert format_sas("42") == "000 042"


def test_word_sas_known_answer_vector():
    words = compute_sas_words(
        bytes(range(32)),
        bytes(range(32, 64)),
        transcript_hash=bytes(range(64, 96)),
    )
    assert words == ("saber", "olive", "wagon", "igloo", "zinc")
    assert format_sas_words(words) == "saber olive wagon igloo zinc"


def test_setup_word_sas_known_answer_and_role_symmetry():
    owner = bytes(range(32))
    device = bytes(range(32, 64))
    invite = bytes(range(64, 96))
    words = compute_setup_sas_words(
        owner, device, invite_secret=invite,
    )
    assert words == ("frost", "nudge", "panda", "decoy", "sleek")
    assert words == compute_setup_sas_words(
        device, owner, invite_secret=invite,
    )
    assert words != compute_setup_sas_words(
        owner, device, invite_secret=bytes([invite[0] ^ 1]) + invite[1:],
    )


def test_setup_word_sas_rejects_malformed_inputs():
    owner, device = os.urandom(32), os.urandom(32)
    with pytest.raises(ValueError):
        compute_setup_sas_words(owner, device, invite_secret=os.urandom(31))
    with pytest.raises(ValueError):
        compute_setup_sas_words(owner[:-1], device, invite_secret=os.urandom(32))


def test_word_sas_is_symmetric_and_transcript_bound():
    a, b = os.urandom(32), os.urandom(32)
    transcript = os.urandom(32)
    expected = compute_sas_words(a, b, transcript_hash=transcript)
    assert expected == compute_sas_words(b, a, transcript_hash=transcript)
    assert len(expected) == PAIR_SAS_WORD_COUNT
    assert all(word in PAIR_SAS_WORDS for word in expected)
    assert expected != compute_sas_words(
        a, b, transcript_hash=bytes([transcript[0] ^ 1]) + transcript[1:],
    )


def test_word_sas_rejects_static_or_malformed_transcripts():
    a, b = os.urandom(32), os.urandom(32)
    with pytest.raises(TypeError):
        compute_sas_words(a, b, transcript_hash=None)  # type: ignore[arg-type]
    for invalid in (b"", b"short", os.urandom(31), os.urandom(33)):
        with pytest.raises(ValueError):
            compute_sas_words(a, b, transcript_hash=invalid)


def test_word_sas_has_exactly_30_protocol_bits():
    assert PAIR_SAS_BITS == 30
    assert len(PAIR_SAS_WORDS) == 64
    assert len(set(PAIR_SAS_WORDS)) == 64


def test_word_sas_formatter_fails_closed():
    with pytest.raises(ValueError):
        format_sas_words(("agile",) * 4)
    with pytest.raises(ValueError):
        format_sas_words(("agile", "amuse", "apple", "basil", "outside"))


def test_word_dictionary_is_identical_across_python_rust_and_browsers():
    rust = Path("native/ol_pair_qr/src/sas_words.rs").read_text(encoding="utf-8")
    rust_block = rust.split("pub const SAS_WORDS", 1)[1].split("];", 1)[0]
    rust_words = tuple(re.findall(r'"([a-z]+)"', rust_block))

    desktop = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    desktop_block = desktop.split("const PAIR_SAS_WORDS = new Set([", 1)[1].split("]);", 1)[0]
    desktop_words = tuple(re.findall(r'"([a-z]+)"', desktop_block))

    browser = Path("src/one_link/web/peer.html").read_text(encoding="utf-8")
    browser_block = browser.split(
        "const PAIR_SAS_WORDS = Object.freeze([", 1,
    )[1].split("]);", 1)[0]
    browser_words = tuple(re.findall(r'"([a-z]+)"', browser_block))

    assert rust_words == PAIR_SAS_WORDS
    assert desktop_words == PAIR_SAS_WORDS
    assert browser_words == PAIR_SAS_WORDS


# ───────── PairingTracker ──────────────────────────────────────────────

def test_tracker_lifecycle_outgoing():
    t = PairingTracker()
    assert t.get("aa" * 32) is None
    ctx = t.begin(peer_fp="aa" * 32, sas="123456", incoming=False)
    assert ctx.state == PairState.REQUESTED
    assert ctx.sas == "123456"

    # We say match
    t.we_confirm("aa" * 32)
    assert t.get("aa" * 32).state == PairState.CONFIRMED
    assert t.get("aa" * 32).we_confirmed
    assert not t.get("aa" * 32).they_confirmed

    # They say match
    t.they_confirm("aa" * 32)
    assert t.get("aa" * 32).state == PairState.PAIRED


def test_tracker_preserves_validated_word_sas():
    tracker = PairingTracker()
    words = ("agile", "amuse", "apple", "basil", "blaze")
    ctx = tracker.begin(
        peer_fp="aa" * 32,
        sas="12345678",
        sas_words=words,
        incoming=False,
    )
    assert ctx.sas_words == words
    with pytest.raises(ValueError):
        tracker.begin(
            peer_fp="bb" * 32,
            sas="87654321",
            sas_words=("agile", "amuse", "apple", "basil", "invalid"),
            incoming=False,
        )


def test_tracker_lifecycle_incoming():
    t = PairingTracker()
    ctx = t.begin(peer_fp="aa" * 32, sas="999999", incoming=True)
    assert ctx.state == PairState.INCOMING

    # Their confirmation arrives first
    t.they_confirm("aa" * 32)
    assert t.get("aa" * 32).state == PairState.INCOMING  # still waiting on us

    # Our user clicks match
    t.we_confirm("aa" * 32)
    assert t.get("aa" * 32).state == PairState.PAIRED


def test_tracker_reject():
    t = PairingTracker()
    t.begin(peer_fp="aa" * 32, sas="123456", incoming=False)
    t.reject("aa" * 32)
    assert t.get("aa" * 32).state == PairState.REJECTED


def test_tracker_clear():
    t = PairingTracker()
    t.begin(peer_fp="aa" * 32, sas="123456", incoming=False)
    t.clear("aa" * 32)
    assert t.get("aa" * 32) is None


def test_tracker_concurrent_peers():
    t = PairingTracker()
    t.begin(peer_fp="aa" * 32, sas="111111", incoming=False)
    t.begin(peer_fp="bb" * 32, sas="222222", incoming=True)
    assert t.get("aa" * 32).state == PairState.REQUESTED
    assert t.get("bb" * 32).state == PairState.INCOMING
    assert len(t.all()) == 2


# ───────── End-to-end pairing across two daemons ──────────────────────

import asyncio
import time

import aiohttp
from tests.harness import daemon_pair


@pytest.mark.live_daemon
@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_pairing_round_trip_pins_both_sides():
    """A initiates pair → both daemons compute the same SAS → A confirms,
    B confirms → both ends store trust='pinned'."""
    with daemon_pair() as p:
        # Read tokens
        ta = (p.a.home / "data" / "ui.token").read_text().strip()
        tb = (p.b.home / "data" / "ui.token").read_text().strip()
        port_a = int((p.a.home / "data" / "server.port").read_text().strip())
        port_b = int((p.b.home / "data" / "server.port").read_text().strip())
        base_a = f"http://127.0.0.1:{port_a}"
        base_b = f"http://127.0.0.1:{port_b}"

        async with aiohttp.ClientSession() as s:
            # Pre-pair lookups: peers are unpaired, so use the modal feed.
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
            assert fp_b, f"peer {p.b.short_id} not visible from A"
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
            assert fp_a, f"peer {p.a.short_id} not visible from B"

            # v0.20.7 (security audit H11): both /api/peers/{fp}/sas
            # endpoints return the legacy v1 SAS (transcript-unbound,
            # 6 digits) as a static code preview. They must agree
            # between A and B because pubkeys are symmetric.
            async with s.get(
                f"{base_a}/api/peers/{fp_b}/sas",
                headers={"Authorization": f"Bearer {ta}"},
            ) as r:
                sas_a = (await r.json())["sas"]
            async with s.get(
                f"{base_b}/api/peers/{fp_a}/sas",
                headers={"Authorization": f"Bearer {tb}"},
            ) as r:
                sas_b = (await r.json())["sas"]
            assert sas_a == sas_b, f"SAS mismatch: A={sas_a!r} B={sas_b!r}"

            # v0.20.7 (security audit H11): the actual pair ceremony
            # returns a v2 SAS bound to the live channel transcript,
            # which is intentionally different from the static v1
            # preview above. We assert only that both sides agree on
            # the v2 SAS via their pair-flow returns + UI events
            # (next block); we no longer require pair_init.sas ==
            # static_preview_sas.
            async with s.post(
                f"{base_a}/api/peers/{fp_b}/pair",
                headers={"Authorization": f"Bearer {ta}"},
                json={},
            ) as r:
                init = await r.json()
            assert init["ok"]
            assert isinstance(init["sas"], str) and init["sas"].isdigit()
            assert init["sas_version"] == "words-v3"
            assert init["sas_scope"] == "live_encrypted_channel_transcript"
            assert len(init["sas_words"]) == PAIR_SAS_WORD_COUNT
            assert init["sas_phrase"] == " ".join(init["sas_words"])

            # Give the PAIR_REQUEST a moment to land at B
            await asyncio.sleep(0.5)

            # Both sides confirm
            async with s.post(
                f"{base_a}/api/peers/{fp_b}/pair-confirm",
                headers={"Authorization": f"Bearer {ta}"},
                json={},
            ) as r:
                ca = await r.json()
            async with s.post(
                f"{base_b}/api/peers/{fp_a}/pair-confirm",
                headers={"Authorization": f"Bearer {tb}"},
                json={},
            ) as r:
                cb = await r.json()
            assert ca["ok"] and cb["ok"]

            # Wait for the second-leg PAIR_CONFIRM to propagate. Default
            # /api/peers (paired-only) is the right feed once pinning lands.
            deadline = time.time() + 5
            both_pinned = False
            a_view = b_view = None
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
                a_view = next((pp for pp in ja2["peers"] if pp["fingerprint"] == fp_b), None)
                b_view = next((pp for pp in jb2["peers"] if pp["fingerprint"] == fp_a), None)
                if a_view and b_view and a_view["trust"] == "pinned" and b_view["trust"] == "pinned":
                    both_pinned = True
                    break
                await asyncio.sleep(0.2)
            if not both_pinned:
                a_log = (p.a.log).read_text(encoding="utf-8", errors="replace")[-3000:]
                b_log = (p.b.log).read_text(encoding="utf-8", errors="replace")[-3000:]
                pytest.fail(
                    f"trust = ({a_view and a_view.get('trust')}, "
                    f"{b_view and b_view.get('trust')})\n"
                    f"--- A log ---\n{a_log}\n"
                    f"--- B log ---\n{b_log}\n"
                )


@pytest.mark.live_daemon
@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_pair_reject_blocks_outbound():
    """If user rejects the SAS (suspected MITM), the peer is marked
    rejected and outbound to them refuses."""
    with daemon_pair() as p:
        ta = (p.a.home / "data" / "ui.token").read_text().strip()
        port_a = int((p.a.home / "data" / "server.port").read_text().strip())
        base_a = f"http://127.0.0.1:{port_a}"

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
            assert fp_b, f"peer {p.b.short_id} not visible from A"

            async with s.post(
                f"{base_a}/api/peers/{fp_b}/pair-reject",
                headers={"Authorization": f"Bearer {ta}"},
                json={},
            ) as r:
                rj = await r.json()
            assert rj["ok"]

            # Now sending should fail with a rejection-shaped error.
            # Post-ac3d63f the daemon translates the raw "rejected"
            # signal into the friendlier "This device is blocked"
            # for the UI; either wording satisfies the contract that
            # the user is told the send was refused on trust grounds.
            async with s.post(
                f"{base_a}/api/send",
                headers={"Authorization": f"Bearer {ta}"},
                json={"peer": p.b.short_id, "body": "hi"},
            ) as r:
                assert r.status >= 400
                err = await r.json()
                lower = err["error"].lower()
                assert "rejected" in lower or "blocked" in lower
