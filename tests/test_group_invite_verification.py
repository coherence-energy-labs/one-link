"""The group invite token, verified — and the forgeries it has to refuse.

The mint has existed for a long time with NO consumer: `one-link://group-invite/<token>` was
generated, copied and shared, and `peer_path_for_deep_link` answered "unsupported one-link route".
These tests cover the consumer, and they are written forgery-first: a verifier that accepts
everything passes a happy-path test, so the happy path is the least interesting assertion here.

The property that carries the most weight is `test_a_forged_invite_cannot_borrow_someone_elses
_fingerprint`. A signature made with the key named INSIDE the token proves only that the token is
self-consistent — anyone can mint that. Recomputing the fingerprint from the key is what ties an
invite to an identity a recipient can recognise.
"""
from __future__ import annotations

import base64
import copy
import json
import time

import pytest

from one_link import identity
from one_link.group_invite import InviteError, verify_group_invite
from one_link.protocol_handler import peer_path_for_deep_link


def _mint(issuer, *, group_id="ab" * 32, name="Design", ttl_ms=7 * 24 * 3600 * 1000,
          issued_ms=None, overrides=None):
    """Mint exactly as `UIServer.api_group_invite_link` does."""
    now = int(time.time() * 1000) if issued_ms is None else issued_ms
    payload = {
        "v": 1,
        "type": "one_link_group_invite",
        "group_id": group_id,
        "name": name,
        "issuer_fp": identity.fingerprint_of(issuer.public_bytes),
        "issuer_pub_hex": issuer.public_bytes.hex(),
        "issued_ms": now,
        "expires_ms": now + ttl_ms,
        "nonce": "kZ8-test-nonce",
    }
    if overrides:
        payload.update(overrides)
    return _seal(payload, issuer)


def _seal(payload, signer):
    signed = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    envelope = {"payload": payload, "signature_hex": signer.sign(signed).hex()}
    raw = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@pytest.fixture(scope="module")
def issuer(tmp_path_factory):
    return identity.load_or_create(tmp_path_factory.mktemp("issuer") / "key")


@pytest.fixture(scope="module")
def attacker(tmp_path_factory):
    """A REAL second key, not a mangled copy of the first. The forgery test is only meaningful if
    the attacker can produce genuinely valid signatures of their own."""
    return identity.load_or_create(tmp_path_factory.mktemp("attacker") / "key")


# ── it works ──────────────────────────────────────────────────────────


def test_a_genuine_invite_verifies_and_names_its_issuer(issuer):
    inv = verify_group_invite(_mint(issuer))
    assert inv.group_id == "ab" * 32
    assert inv.name == "Design"
    assert inv.issuer_fp == identity.fingerprint_of(issuer.public_bytes)
    assert inv.issuer_pub == issuer.public_bytes
    assert inv.expires_in_ms > 0


def test_the_deep_link_the_app_MINTS_is_one_the_app_ACCEPTS(issuer):
    """The regression that started this: the app generated a URL it then refused."""
    token = _mint(issuer)
    path = peer_path_for_deep_link(f"one-link://group-invite/{token}")
    assert path.startswith("/peer?")
    assert "group_invite=" in path
    # ...and the token survives the round trip intact, or the screen it opens verifies nothing.
    from urllib.parse import parse_qs, urlparse
    assert parse_qs(urlparse(path).query)["group_invite"][0] == token


# ── the forgeries ─────────────────────────────────────────────────────


def test_a_forged_invite_cannot_borrow_someone_elses_fingerprint(issuer, attacker):
    """THE property. The attacker signs correctly with their OWN key, but claims the issuer's
    fingerprint -- so the recipient sees a name they trust. A verifier that only checks the
    signature against the key inside the token accepts this without complaint."""
    forged = _mint(attacker, overrides={
        "issuer_fp": identity.fingerprint_of(issuer.public_bytes),
    })
    # The signature itself is perfectly valid -- that is what makes this the dangerous case.
    with pytest.raises(InviteError, match="does not match its public key"):
        verify_group_invite(forged)


def test_an_edited_payload_is_refused(issuer):
    """Change the group being joined after signing."""
    token = _mint(issuer)
    raw = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
    tampered = copy.deepcopy(raw)
    tampered["payload"]["group_id"] = "cd" * 32
    blob = json.dumps(tampered, separators=(",", ":"), sort_keys=True).encode()
    with pytest.raises(InviteError, match="signature does not verify"):
        verify_group_invite(base64.urlsafe_b64encode(blob).decode().rstrip("="))


def test_an_added_field_is_refused(issuer):
    """The signature covers the whole payload, so smuggling a field in breaks it."""
    token = _mint(issuer)
    raw = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
    raw["payload"]["admin"] = True
    blob = json.dumps(raw, separators=(",", ":"), sort_keys=True).encode()
    with pytest.raises(InviteError, match="signature does not verify"):
        verify_group_invite(base64.urlsafe_b64encode(blob).decode().rstrip("="))


def test_an_expired_invite_is_refused(issuer):
    old = int(time.time() * 1000) - 10 * 24 * 3600 * 1000
    token = _mint(issuer, issued_ms=old, ttl_ms=24 * 3600 * 1000)
    with pytest.raises(InviteError, match="has expired"):
        verify_group_invite(token)


def test_an_invite_from_the_future_is_refused(issuer):
    """A wrong clock is not a small problem here: if `issued_ms` cannot be trusted then neither
    can `expires_ms`, which is the only thing bounding the token's life."""
    ahead = int(time.time() * 1000) + 60 * 60 * 1000
    with pytest.raises(InviteError, match="issued in the future"):
        verify_group_invite(_mint(issuer, issued_ms=ahead))


def test_an_invite_that_expires_before_it_was_issued_is_refused(issuer):
    now = int(time.time() * 1000)
    token = _mint(issuer, overrides={"issued_ms": now, "expires_ms": now - 1})
    with pytest.raises(InviteError):
        verify_group_invite(token)


def test_a_different_token_type_is_refused(issuer):
    """A self-mesh enrolment token must not be redeemable as a group invite."""
    token = _mint(issuer, overrides={"type": "one_link_self_mesh_invite"})
    with pytest.raises(InviteError, match="not a group invite"):
        verify_group_invite(token)


def test_a_future_version_is_refused_rather_than_guessed(issuer):
    with pytest.raises(InviteError, match="unsupported group invite version"):
        verify_group_invite(_mint(issuer, overrides={"v": 2}))


@pytest.mark.parametrize("junk", [
    "", "   ", "not-base64!!", "a" * 12,                      # too short for the shape gate
    base64.urlsafe_b64encode(b"not json at all").decode().rstrip("="),
    base64.urlsafe_b64encode(b'{"payload":{}}').decode().rstrip("="),
    base64.urlsafe_b64encode(b'["not","an","envelope"]').decode().rstrip("="),
])
def test_garbage_is_refused_without_raising_anything_but_InviteError(junk):
    """Every rejection path must arrive as InviteError. A stray TypeError from a decoder is a
    crash in the caller, and this input arrives from a stranger's message."""
    with pytest.raises(InviteError):
        verify_group_invite(junk)


def test_an_oversized_token_is_refused_before_it_is_parsed():
    with pytest.raises(InviteError):
        verify_group_invite("A" * 9000)


def test_a_bad_public_key_length_is_refused(issuer):
    token = _mint(issuer, overrides={"issuer_pub_hex": "aa" * 16})
    with pytest.raises(InviteError, match="not an Ed25519 public key"):
        verify_group_invite(token)


def test_boolean_timestamps_are_not_accepted_as_integers(issuer):
    """`True == 1` in Python, so an isinstance(int) check alone lets a bool through."""
    token = _mint(issuer, overrides={"expires_ms": True})
    with pytest.raises(InviteError):
        verify_group_invite(token)
