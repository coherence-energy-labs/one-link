"""Verify a group invite token — the consumer the mint never had.

WHAT WAS MISSING. `UIServer.api_group_invite_link` signs a `one-link://group-invite/<token>`
URL and `peer.html` offers a "Copy invite" button, so from the outside the feature looked
finished. Nothing anywhere decoded that token: not the phone, not the desktop, not the deep-link
handler, which accepted exactly one route (`self-mesh/enroll`). A user could copy an invite and
send it, and the person who received it had no path that consumed it. `LAUNCH_BLOCKERS.md#9`
recorded this as a phone-UI gap; it was a missing consumer on every surface.

WHAT THIS MODULE IS, AND IS NOT. It answers one question and answers it completely:

    is this token a genuine, unexpired invite, and WHO issued it?

It does NOT grant membership, and must never be made to. The mint is explicit about why:
*"the token lets a paired device prove which group it is asking to join. A group admin still
signs the ADD_MEMBER event, preserving the group authority model instead of turning links into
ambient access."* A verified invite is therefore an INTRODUCTION — enough to show the invitee
what they are being asked to join and to carry a request to an admin. Anything that turns the
output of this function directly into membership has re-introduced ambient access.

THE BINDING THAT MATTERS. The payload carries both `issuer_fp` and `issuer_pub_hex`, and the
signature is verified under the key in the token itself — so a valid signature alone proves only
that *whoever wrote this payload owned the key they named in it*. Anyone can mint that. The
fingerprint is therefore recomputed from the public key and required to match, which is what ties
the invite to an identity the recipient can actually recognise. Without that check, an attacker
mints a perfectly-signed invite carrying a trusted contact's fingerprint and their own key.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass
from typing import Any

from one_link.identity import fingerprint_of, verify as verify_signature

#: The mint emits unpadded base64url. Bound the length before any decoding: an invite is ~400
#: bytes, and a megabyte of "token" is an attack on the parser, not a mistake.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,8192}$")

#: Refuse a token whose decoded body is implausible for an invite, before handing it to a parser.
_MAX_DECODED = 16 * 1024

#: Clocks disagree. A minted-in-the-future invite is tolerated by this much and no more; beyond it
#: the issuer's clock is wrong enough that `expires_ms` cannot be trusted either.
_FUTURE_SKEW_MS = 5 * 60 * 1000

INVITE_TYPE = "one_link_group_invite"


class InviteError(ValueError):
    """A token that cannot be trusted, with a reason a human can act on."""


@dataclass(frozen=True)
class VerifiedInvite:
    """A token that verified. Membership is still an admin's decision."""

    group_id: str
    name: str
    issuer_fp: str
    issuer_pub: bytes
    issued_ms: int
    expires_ms: int
    nonce: str

    @property
    def expires_in_ms(self) -> int:
        return self.expires_ms - int(time.time() * 1000)


def _decode_token(token: str) -> bytes:
    token = str(token or "").strip()
    if not token:
        raise InviteError("group invite link carries no token")
    if not _TOKEN_RE.fullmatch(token):
        raise InviteError("group invite token is malformed")
    # `validate=True` so stray characters are an error rather than being silently dropped --
    # silent dropping would let two different tokens decode to the same bytes.
    padding = "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode(token + padding)
    except (binascii.Error, ValueError) as exc:
        raise InviteError(f"group invite token is not valid base64url ({exc})") from exc
    if len(raw) > _MAX_DECODED:
        raise InviteError("group invite token is implausibly large")
    return raw


def verify_group_invite(token: str, *, now_ms: int | None = None) -> VerifiedInvite:
    """Return the invite this token attests to, or raise `InviteError` saying why not.

    Fails closed on every path. The caller gets a verified introduction or an exception; there is
    deliberately no "probably fine" return value for a UI to render optimistically.
    """
    raw = _decode_token(token)

    try:
        envelope: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InviteError(f"group invite token is not JSON ({exc})") from exc
    if not isinstance(envelope, dict):
        raise InviteError("group invite token is not an envelope")

    payload = envelope.get("payload")
    sig_hex = envelope.get("signature_hex")
    if not isinstance(payload, dict) or not isinstance(sig_hex, str):
        raise InviteError("group invite envelope is missing its payload or signature")

    if payload.get("v") != 1:
        raise InviteError(f"unsupported group invite version {payload.get('v')!r}")
    if payload.get("type") != INVITE_TYPE:
        raise InviteError(f"not a group invite ({payload.get('type')!r})")

    pub_hex = payload.get("issuer_pub_hex")
    claimed_fp = payload.get("issuer_fp")
    group_id = payload.get("group_id")
    if not isinstance(pub_hex, str) or not isinstance(claimed_fp, str) or not isinstance(group_id, str):
        raise InviteError("group invite payload is missing its issuer or group")
    try:
        pub = bytes.fromhex(pub_hex)
        bytes.fromhex(group_id)                       # shape only; membership decides the rest
    except ValueError as exc:
        raise InviteError(f"group invite carries malformed hex ({exc})") from exc
    if len(pub) != 32:
        raise InviteError("group invite issuer key is not an Ed25519 public key")

    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError as exc:
        raise InviteError(f"group invite signature is not hex ({exc})") from exc

    # Re-serialise EXACTLY as the mint did. Any added, removed or reordered field changes these
    # bytes and the signature stops verifying -- which is also why duplicate JSON keys cannot be
    # used to show one payload to the verifier and another to a reader.
    signed = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if not verify_signature(pub, sig, signed):
        raise InviteError("group invite signature does not verify")

    # THE BINDING. A signature made with the key named in the token proves only self-consistency;
    # anyone can mint that. Recomputing the fingerprint is what stops an attacker presenting a
    # trusted contact's fingerprint over their own key.
    if fingerprint_of(pub) != claimed_fp:
        raise InviteError(
            "group invite issuer fingerprint does not match its public key -- the invite claims "
            "to be from someone it was not signed by")

    issued_ms = payload.get("issued_ms")
    expires_ms = payload.get("expires_ms")
    if not isinstance(issued_ms, int) or not isinstance(expires_ms, int):
        # `bool` is an int subclass; reject it explicitly rather than treating True as 1.
        raise InviteError("group invite timestamps are missing or malformed")
    if isinstance(issued_ms, bool) or isinstance(expires_ms, bool):
        raise InviteError("group invite timestamps are malformed")

    now = int(time.time() * 1000) if now_ms is None else int(now_ms)
    if expires_ms <= now:
        raise InviteError("group invite has expired")
    if issued_ms > now + _FUTURE_SKEW_MS:
        raise InviteError("group invite was issued in the future; refusing to trust its expiry")
    if expires_ms <= issued_ms:
        raise InviteError("group invite expires before it was issued")

    name = payload.get("name")
    nonce = payload.get("nonce")
    return VerifiedInvite(
        group_id=group_id,
        name=name if isinstance(name, str) else "",
        issuer_fp=claimed_fp,
        issuer_pub=pub,
        issued_ms=issued_ms,
        expires_ms=expires_ms,
        nonce=nonce if isinstance(nonce, str) else "",
    )


__all__ = ["InviteError", "VerifiedInvite", "verify_group_invite", "INVITE_TYPE"]
