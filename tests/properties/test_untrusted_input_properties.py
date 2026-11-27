"""Properties of the code that handles bytes and names a stranger chose.

Example-based tests pin the cases someone thought of. These state what must
hold for every input and let Hypothesis look for the one nobody thought of.
"""

from __future__ import annotations

import asyncio
import json
import unicodedata
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from one_link import identity, peer_admission, transfer_names, wire

# ─── wire framing ───────────────────────────────────────────────────


def _read(data: bytes, ceiling: int) -> bytes:
    async def go() -> bytes:
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return await wire.read_frame(reader, ceiling)

    return asyncio.run(go())


@given(payload=st.binary(max_size=4096), ceiling=st.integers(min_value=0, max_value=8192))
@settings(max_examples=150, deadline=None)
def test_a_frame_is_returned_whole_or_refused(payload: bytes, ceiling: int) -> None:
    framed = len(payload).to_bytes(4, "big") + payload
    if len(payload) <= ceiling:
        assert _read(framed, ceiling) == payload
    else:
        try:
            _read(framed, ceiling)
        except ValueError as exc:
            assert "frame too large" in str(exc)
        else:
            raise AssertionError("an oversize frame was returned")


# ─── JSON depth check ───────────────────────────────────────────────

_text = st.text(alphabet='{}[]"\\ab:, \n', max_size=12)
_json = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), _text),
    lambda children: st.one_of(
        st.lists(children, max_size=4), st.dictionaries(_text, children, max_size=4)
    ),
    max_leaves=25,
)


def _depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max((_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(v) for v in value), default=0)
    return 0


@given(value=_json, limit=st.integers(min_value=1, max_value=6))
@settings(max_examples=300, deadline=None)
def test_depth_check_is_exact_for_real_json(value: object, limit: int) -> None:
    # Strings full of brackets, quotes and backslashes must not count as
    # nesting, and real nesting must never be missed.
    encoded = json.dumps(value).encode("utf-8")
    try:
        wire._check_json_depth(encoded, limit)
    except ValueError:
        assert _depth(value) > limit
    else:
        assert _depth(value) <= limit


@given(data=st.binary(max_size=512), limit=st.integers(min_value=1, max_value=8))
@settings(max_examples=300, deadline=None)
def test_depth_check_only_ever_raises_value_error(data: bytes, limit: int) -> None:
    try:
        wire._check_json_depth(data, limit)
    except ValueError:
        pass


@given(data=st.binary(max_size=512), limit=st.integers(min_value=1, max_value=8))
@settings(max_examples=300, deadline=None)
def test_whatever_the_parser_accepts_was_within_the_limit(data: bytes, limit: int) -> None:
    # The check and the parser must agree on every input the parser accepts:
    # nothing parseable may be deeper than the check allowed.
    try:
        wire._check_json_depth(data, limit)
    except ValueError:
        return
    try:
        value = json.loads(data)
    except (ValueError, RecursionError):
        return
    assert _depth(value) <= limit


# ─── received file names ────────────────────────────────────────────

_RESERVED = frozenset({"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"})
_BIDI = set(transfer_names._SPOOFING_CODEPOINTS)


@given(name=st.text(max_size=300), max_bytes=st.integers(min_value=16, max_value=240))
@settings(max_examples=400, deadline=None)
def test_a_cleaned_name_is_always_one_safe_leaf(name: str, max_bytes: int) -> None:
    clean = transfer_names.safe_transfer_name(name, reserved=_RESERVED, max_bytes=max_bytes)
    assert clean
    assert "/" not in clean and "\\" not in clean and ":" not in clean
    assert clean not in {".", ".."}
    assert len(clean.encode("utf-8", errors="ignore")) <= max_bytes
    assert not any(ord(c) < 0x20 or ord(c) == 0x7F or ord(c) in _BIDI for c in clean)
    assert not any(unicodedata.bidirectional(c) in {"LRO", "RLO", "LRE", "RLE", "PDF"} for c in clean)


@given(name=st.text(max_size=120))
@settings(max_examples=300, deadline=None)
def test_cleaning_a_name_twice_changes_nothing_more(name: str) -> None:
    once = transfer_names.safe_transfer_name(name, reserved=_RESERVED, max_bytes=240)
    assert transfer_names.safe_transfer_name(once, reserved=_RESERVED, max_bytes=240) == once


# ─── bounded bookkeeping and budgets ────────────────────────────────


@given(
    maxlen=st.integers(min_value=1, max_value=8),
    keys=st.lists(st.integers(min_value=0, max_value=20), max_size=80),
)
@settings(max_examples=200, deadline=None)
def test_bounded_dict_never_exceeds_its_bound_and_keeps_the_newest(maxlen, keys) -> None:
    store: peer_admission.BoundedDict[int, int] = peer_admission.BoundedDict(maxlen)
    for step, key in enumerate(keys):
        store[key] = step
        assert len(store) <= maxlen
        assert key in store and store[key] == step
    newest = list(dict.fromkeys(reversed(keys)))[:maxlen]
    assert set(store) == set(newest)


@given(
    steps=st.lists(
        st.tuples(st.floats(min_value=0, max_value=30), st.integers(min_value=0, max_value=4096)),
        max_size=200,
    )
)
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_a_stranger_never_gets_more_than_burst_plus_refill(steps) -> None:
    now = {"t": 0.0}
    budget = peer_admission.StrangerBudget(clock=lambda: now["t"])
    frames = admitted_bytes = 0
    for wait, size in steps:
        now["t"] += wait
        if budget.admit(size):
            frames += 1
            admitted_bytes += size
    elapsed = now["t"]
    assert frames <= peer_admission.STRANGER_FRAME_BURST + elapsed * peer_admission.STRANGER_FRAMES_PER_S + 1e-6
    assert admitted_bytes <= peer_admission.STRANGER_BYTE_BURST + elapsed * peer_admission.STRANGER_BYTES_PER_S + 1e-6


# ─── peer name resolution ───────────────────────────────────────────

_names = st.text(alphabet="abcXYZ 0123", min_size=1, max_size=6)


def _peer(index: int, hostname: str, alias: str) -> SimpleNamespace:
    fingerprint = f"{index:02x}" * 32
    return SimpleNamespace(
        fingerprint=fingerprint,
        short_id=fingerprint[:8],
        hostname=hostname,
        local_alias=alias,
        display_name=alias or hostname,
    )


@given(
    labels=st.lists(st.tuples(_names, _names), min_size=1, max_size=5),
    needle=st.one_of(_names, st.text(alphabet="0123456789abcdef", max_size=12)),
)
@settings(max_examples=300, deadline=None)
def test_a_name_resolves_to_a_peer_it_names_or_to_nothing(labels, needle) -> None:
    peers = [_peer(i + 1, host, alias) for i, (host, alias) in enumerate(labels)]
    found = peer_admission.unique_pinned_match(needle, peers)
    lowered = needle.strip().lower()

    def names(peer) -> list[str]:
        return [v.lower() for v in (peer.hostname, peer.local_alias, peer.display_name) if v]

    whole = [p for p in peers if lowered in (p.fingerprint, p.short_id, *names(p))]
    prefix = [p for p in peers if len(lowered) >= 8 and p.fingerprint.startswith(lowered)]
    part = [p for p in peers if any(lowered in name for name in names(p))]
    # The first rule that matches anything decides, and it must match one peer.
    deciding = next((group for group in (whole, prefix, part) if group), []) if lowered else []
    expected = deciding[0].fingerprint if len(deciding) == 1 else None
    assert found == expected
    if found is not None:
        assert found in {p.fingerprint for p in peers}


# ─── sealed identity key ────────────────────────────────────────────


@given(
    passphrase=st.binary(min_size=1, max_size=64),
    other=st.binary(min_size=1, max_size=64),
    flip=st.integers(min_value=0, max_value=10_000),
)
@settings(max_examples=12, deadline=None)
def test_sealed_key_opens_only_with_its_passphrase_and_only_intact(passphrase, other, flip) -> None:
    import base64

    original = identity._SEALED_LOG2_N
    identity._SEALED_LOG2_N = 15  # the cheapest cost the reader accepts
    try:
        key = Ed25519PrivateKey.generate()
        blob = identity._seal_private_key(key, passphrase)
        opened, protection = identity.decode_private_key_file(blob, passphrase)
        assert protection == identity.PROTECTION_SEALED
        assert opened.private_bytes_raw() == key.private_bytes_raw()

        if other != passphrase:
            try:
                identity.decode_private_key_file(blob, other)
            except ValueError:
                pass
            else:
                raise AssertionError("opened with the wrong passphrase")

        body = blob.strip()[len(identity._SEALED_BEGIN) : -len(identity._SEALED_END)]
        raw = bytearray(base64.b64decode(body))
        position = flip % len(raw)
        raw[position] ^= 0x01
        damaged = (
            identity._SEALED_BEGIN + b"\n" + base64.encodebytes(bytes(raw)) + identity._SEALED_END + b"\n"
        )
        try:
            identity.decode_private_key_file(damaged, passphrase)
        except ValueError:
            pass
        else:
            raise AssertionError(f"a sealed key with byte {position} changed still opened")
    finally:
        identity._SEALED_LOG2_N = original
