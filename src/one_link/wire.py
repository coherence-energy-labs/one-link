"""Wire protocol: length-prefixed binary frames + JSON message envelopes.

Frame format on the wire:
    [4-byte big-endian length N] [N bytes payload]

Frames carry one of two payload kinds:
    - handshake: raw bytes (HELLO/CHALLENGE/AUTH binary blobs, see channel.py)
    - encrypted: ChaCha20-Poly1305 ciphertext containing a JSON message

Inside an encrypted frame, the plaintext is a JSON object:
    {"t": "<type>", "id": "<msg_id>", "ts": <unix_ms>, "from": "<short_id>", ...}

Message types (t):
    TEXT       — chat message; "body": str
    FILE_OFFER — sender announces a file; "name": str, "size": int, "blob": <hex sha256>
    FILE_CHUNK — file content; "blob": <hex>, "seq": int, "data": <base64>, "eof": bool
    ACK        — acknowledgement; "of": <msg_id>
    PING       — keepalive
    PONG       — keepalive reply
"""

from __future__ import annotations

import asyncio
import json
import math
import time
import uuid
from collections.abc import Callable
from typing import Any

MAX_FRAME = 16 * 1024 * 1024  # 16 MiB hard cap per frame; chunked above this

# Frame ceilings by trust stage. A peer earns the full ceiling only after the
# owner has pinned it; before that every byte it sends is attacker-chosen.
#
# HANDSHAKE_MAX_FRAME bounds the unauthenticated first flights. The largest
# legitimate one is the post-quantum REPLY (about 1.3 KiB); 16 KiB leaves room
# for a sealed envelope and future fields while keeping a pre-authentication
# connection from buffering megabytes.
HANDSHAKE_MAX_FRAME = 16 * 1024

# UNPINNED_MAX_FRAME bounds an authenticated-but-unpinned peer. Such a peer
# may only exchange CAPS, keepalives and the pairing ceremony, all of which
# are a few kilobytes.
UNPINNED_MAX_FRAME = 256 * 1024

# v0.20.7 (security audit M7): cap JSON nesting on encrypted-frame
# plaintexts. Without this, a malicious peer can ship `{"a":{"a":...}}`
# nested 1000+ levels deep and drive CPython's recursive json
# decoder into RecursionError. The receive loop catches that as a
# generic Exception and closes the channel — annoying but bounded;
# combined with slowloris-style pinning it becomes a cheap log-spam
# / fd-churn primitive. 64 levels is well beyond any legitimate
# One Link payload (the deepest live shape today is ~6 levels) and
# below the CPython recursion floor with comfortable headroom.
MAX_JSON_DEPTH = 64


# A frame may not materialise more than this many JSON containers. json.loads
# allocates one Python object per container, so an unbounded count turns a
# 16 MiB frame of ``[],[],[]...`` into hundreds of megabytes of lists.
MAX_JSON_CONTAINERS = 1_000_000

_NON_BRACKET_BYTES = bytes(b for b in range(256) if b not in b"{}[]")
_OPENERS = frozenset(b"{[")
# String literals are removed window by window so that a frame made of
# millions of tiny literals never has more than one window's worth of split
# parts alive at once.
_STRIP_WINDOW = 1 << 20


def _json_brackets(data: bytes) -> bytes:
    """Return only the structural brackets of ``data``, in order.

    Brackets inside string literals are dropped. Every step is a C-level
    ``bytes`` primitive, so the cost is a few passes over the frame however
    the content is arranged.
    """
    if b"\\" in data:
        # Drop escaped backslashes, then escaped quotes. What remains has no
        # escaped quote, so quotes alternate strictly between open and close.
        data = data.replace(b"\\\\", b"").replace(b'\\"', b"")
    out: list[bytes] = []
    in_string = False
    view = memoryview(data)
    for offset in range(0, len(data), _STRIP_WINDOW):
        parts = bytes(view[offset : offset + _STRIP_WINDOW]).split(b'"')
        outside = parts[1::2] if in_string else parts[0::2]
        out.append(b"".join(outside).translate(None, _NON_BRACKET_BYTES))
        if (len(parts) - 1) & 1:
            in_string = not in_string
    return b"".join(out)


def _check_json_depth(data: bytes, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Reject a JSON byte string whose nesting exceeds ``max_depth`` or whose
    container count exceeds ``MAX_JSON_CONTAINERS``. Raises ValueError.

    Runs before json.loads so a hostile frame is refused before any object is
    built. Brackets inside string literals do not count.

    Nesting can never be deeper than the number of opening brackets, so a
    frame with few brackets (every chunk and chat frame) is cleared by two
    ``bytes.count`` calls. Only frames with many brackets take the exact path,
    and that path walks brackets alone.
    """
    if data.count(b"{") + data.count(b"[") <= max_depth:
        return
    brackets = _json_brackets(data)
    if len(brackets) > 2 * MAX_JSON_CONTAINERS:
        raise ValueError(
            f"JSON too complex (>{MAX_JSON_CONTAINERS} containers) — frame rejected"
        )
    depth = 0
    for c in brackets:
        if c in _OPENERS:
            depth += 1
            if depth > max_depth:
                raise ValueError(
                    f"JSON nesting too deep (>{max_depth}) — frame rejected"
                )
        elif depth > 0:
            depth -= 1


async def read_frame(
    reader: asyncio.StreamReader,
    max_frame: int | Callable[[], int] = MAX_FRAME,
) -> bytes:
    """Read one length-prefixed frame, refusing any length above ``max_frame``.

    The length is checked before a single payload byte is buffered, so the
    caller's ceiling is also the most memory one frame can pin. ``max_frame``
    is clamped to ``MAX_FRAME``; a caller cannot raise the protocol ceiling.

    ``max_frame`` may be a callable. It is evaluated after the length prefix
    arrives, so a ceiling that depends on the sender's current trust reflects
    the moment the frame was sent, not the moment the read began waiting.
    """
    header = await reader.readexactly(4)
    n = int.from_bytes(header, "big")
    limit = max_frame() if callable(max_frame) else max_frame
    if limit > MAX_FRAME:
        limit = MAX_FRAME
    if n > limit:
        raise ValueError(f"frame too large: {n} > {limit}")
    return await reader.readexactly(n)


def write_frame_nowait(writer: asyncio.StreamWriter, payload: bytes) -> None:
    if len(payload) > MAX_FRAME:
        raise ValueError(f"payload too large: {len(payload)} > {MAX_FRAME}")
    writer.write(len(payload).to_bytes(4, "big") + payload)


async def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    write_frame_nowait(writer, payload)
    await writer.drain()


def now_ms() -> int:
    return int(time.time() * 1000)


def new_msg_id() -> str:
    return uuid.uuid4().hex


def make_msg(t: str, sender_short_id: str, **fields: Any) -> dict[str, Any]:
    msg: dict[str, Any] = {
        "t": t,
        "id": new_msg_id(),
        "ts": now_ms(),
        "from": sender_short_id,
    }
    msg.update(fields)
    return msg


def encode_msg(msg: dict[str, Any]) -> bytes:
    if not isinstance(msg, dict):
        raise ValueError("message must be a JSON object")
    try:
        encoded = json.dumps(
            msg,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("message is not finite JSON") from exc
    if len(encoded) > MAX_FRAME:
        raise ValueError(f"encoded message too large: {len(encoded)} > {MAX_FRAME}")
    return encoded


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON field: {key}")
        out[key] = value
    return out


def _parse_finite_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    return value


def _reject_json_constant(raw: str) -> None:
    raise ValueError(f"non-standard JSON constant: {raw}")


def decode_msg(data: bytes) -> dict[str, Any]:
    # v0.20.7 (security audit M7 + L3): bound JSON nesting before
    # json.loads runs, then enforce that the top-level value is an
    # object. Old behavior accepted JSON null / array / string and
    # downstream `msg.get("t")` raised AttributeError or TypeError,
    # which the recv loop swallowed and closed the channel —
    # functional but log-noisy and cheap to drive.
    if not isinstance(data, bytes):
        raise ValueError("frame payload must be bytes")
    if len(data) > MAX_FRAME:
        raise ValueError(f"frame too large: {len(data)} > {MAX_FRAME}")
    _check_json_depth(data)
    try:
        out = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object,
            parse_float=_parse_finite_float,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ValueError("frame is not valid JSON") from exc
    if not isinstance(out, dict):
        raise ValueError("frame must be a JSON object")
    return out
