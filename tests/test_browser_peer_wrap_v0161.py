"""Browser-as-peer fail-closed identity encryption contract.

New and migrated browser identities are committed only inside a v2
AES-256-GCM envelope.  A digest-pinned first-party Rust/WASM worker derives the
key with one exact Argon2id-v19 profile.  Legacy PBKDF2 envelopes are
decrypt-only and must migrate atomically before networking becomes ready.

  Reach:  forensic exfiltration of OPFS no longer recovers the
          private key. Wrong passphrase = AES-GCM tag mismatch
          = no plaintext.
  Hide:   the wrapped envelope's `private_key_jwk` is gone from
          on-disk JSON. Only `ct_b64u` (opaque ciphertext) +
          KDF params + IV are stored, plus the always-public
          fingerprint + public key.
  Async:  identity unlock is async and memory-hard off the main thread. Boot
          stops at the unlock gate until the user enters the
          right passphrase.
  Depth:  KDF params are exact, authenticated envelope metadata. Oversized or
          downgraded profiles are rejected before worker allocation.

Tests pin the envelope shape, KDF params, AES-GCM contract, the
unlock/setup gates, atomic rotation, and the no-plaintext-downgrade policy.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


# ───────── envelope shape ───────────────────────────────────────────

def test_wrap_function_present(peer_html: str):
    """The single source-of-truth wrap helper. Don't rename — every
    consumer (set-passphrase, change-passphrase) routes through it."""
    assert "async function wrapIdentity(rec, passphrase)" in peer_html


def test_unwrap_function_present(peer_html: str):
    assert "async function unwrapIdentity(envelope, passphrase)" in peer_html


def test_is_wrapped_envelope_helper_present(peer_html: str):
    """Boot needs to distinguish envelope-vs-record without unwrapping;
    isWrappedEnvelope is the single check."""
    assert "function isWrappedEnvelope(rec)" in peer_html


def test_envelope_carries_kdf_metadata(peer_html: str):
    """The envelope MUST store enough KDF metadata to verify a
    passphrase without out-of-band info: algorithm name, salt,
    iteration count. Without these, future-ship rotation to a
    stronger KDF would orphan existing envelopes."""
    idx = peer_html.find("async function _wrapIdentityV2")
    snippet = peer_html[idx:idx + 2500]
    assert '"argon2id-v19"' in snippet
    assert "kdf_memory_kib" in snippet
    assert "kdf_time_cost" in snippet
    assert "kdf_parallelism" in snippet
    assert "kdf_salt_b64u" in snippet
    assert "iv_b64u" in snippet
    assert "ct_b64u" in snippet


def test_envelope_keeps_public_material_outside_wrap(peer_html: str):
    """Public fingerprint + public key MUST live OUTSIDE the
    ciphertext so the unlock UI can show "this is the identity
    you're unlocking" without first having decrypted. Putting
    them inside breaks the unlock UX with no security gain (they're
    public material)."""
    idx = peer_html.find("async function _wrapIdentityV2")
    snippet = peer_html[idx:idx + 2500]
    # The envelope object construction includes both fingerprint and
    # public_key_b64u as TOP-LEVEL fields, alongside ct_b64u.
    assert "fingerprint: rec.fingerprint" in snippet
    assert "public_key_b64u: rec.public_key_b64u" in snippet


def test_envelope_records_wrapped_timestamp(peer_html: str):
    """`wrapped_ms` lets the unlock UI show "wrapped at X" so a user
    investigating "is this stale?" has a real signal."""
    idx = peer_html.find("async function _wrapIdentityV2")
    snippet = peer_html[idx:idx + 2500]
    assert "wrapped_ms" in snippet
    assert "Date.now()" in snippet


# ───────── KDF contract ─────────────────────────────────────────────

def test_kdf_uses_exact_argon2id_profile_in_worker(peer_html: str):
    idx = peer_html.find("async function _deriveArgonAesKey")
    snippet = peer_html[idx:idx + 4500]
    assert '"/browser-crypto/argon2id-worker.js"' in snippet
    assert "IDENTITY_ARGON_MEMORY_KIB" in snippet
    assert "IDENTITY_ARGON_TIME_COST" in snippet
    assert "IDENTITY_ARGON_PARALLELISM" in snippet
    assert "IDENTITY_KDF_TIMEOUT_MS" in snippet


def test_legacy_pbkdf2_is_decrypt_only(peer_html: str):
    idx = peer_html.find("async function _deriveLegacyAesKey")
    snippet = peer_html[idx:idx + 1400]
    assert '"PBKDF2"' in snippet
    assert '"SHA-256"' in snippet
    assert '["decrypt"]' in snippet
    assert '["encrypt", "decrypt"]' not in snippet


def test_kdf_iterations_at_owasp_floor(peer_html: str):
    """OWASP 2023 minimum for PBKDF2-SHA256 is 600,000. Don't
    silently lower — that turns a real defense into theater."""
    assert "KDF_ITERATIONS_DEFAULT = 600000" in peer_html


def test_kdf_uses_16_byte_random_salt(peer_html: str):
    """16 bytes is the standard NIST salt size. Don't truncate —
    smaller salts collide on the order of 2^(salt_bits/2) globally
    via birthday."""
    assert "IDENTITY_SALT_BYTES = 16" in peer_html


def test_kdf_passphrase_min_length_enforced(peer_html: str):
    """The production setup floor is twelve characters and encoded bytes are bounded."""
    idx = peer_html.find("async function wrapIdentity")
    snippet = peer_html[idx:idx + 1500]
    assert "IDENTITY_PASSPHRASE_MIN_CHARS" in snippet
    assert "IDENTITY_PASSPHRASE_MAX_BYTES = 1024" in peer_html


def test_kdf_aes_key_not_extractable(peer_html: str):
    """The derived AES key MUST be marked non-extractable so a JS
    bug or extension can't read it back to clear text via
    crypto.subtle.exportKey('raw'). Defense in depth: the key
    only ever does encrypt+decrypt."""
    idx = peer_html.find("async function _deriveArgonAesKey")
    snippet = peer_html[idx:idx + 5000]
    assert '"raw", rawKey, { name: "AES-GCM" }, false' in snippet


def test_kdf_passphrase_not_kept_in_memory(peer_html: str):
    """After deriving the AES key we discard the passphrase. The
    `state` object holds the unwrapped record + the wrapped
    envelope, NOT the passphrase. Verify by absence."""
    # The state declaration MUST list rec + envelope only.
    idx = peer_html.find("function createPeerIdentity() {")
    end = peer_html.find("function stagePending", idx)
    state_decl = peer_html[idx:end]
    assert "let rec = null;" in state_decl
    assert "let envelope = null;" in state_decl
    assert "passphrase" not in state_decl.lower()


# ───────── AES-GCM contract ─────────────────────────────────────────

def test_aes_gcm_iv_is_12_bytes(peer_html: str):
    """AES-GCM standard IV is 12 bytes (96 bits). Bigger isn't
    safer; smaller breaks the security proof."""
    assert "IDENTITY_IV_BYTES = 12" in peer_html


def test_aes_gcm_uses_per_envelope_random_iv(peer_html: str):
    """IV reuse across encryptions with the same key is catastrophic
    for AES-GCM — leaks the XOR of plaintexts. Each wrap MUST get
    a fresh `_randomBytes(IV_BYTES)`."""
    idx = peer_html.find("async function _wrapIdentityV2")
    snippet = peer_html[idx:idx + 1500]
    assert "_randomBytes(IDENTITY_IV_BYTES)" in snippet


def test_aes_gcm_uses_random_salt(peer_html: str):
    """Salt MUST be fresh per wrap. Same KDF + same passphrase +
    same salt = same key, which combined with IV reuse would lose
    GCM's security."""
    idx = peer_html.find("async function _wrapIdentityV2")
    snippet = peer_html[idx:idx + 1500]
    assert "_randomBytes(IDENTITY_SALT_BYTES)" in snippet


def test_aes_gcm_decrypt_failure_surfaces_as_wrong_passphrase(peer_html: str):
    """The raw GCM tag-mismatch exception is opaque ("OperationError").
    Surface it as a semantic "wrong passphrase" so the unlock UI
    can show a helpful message."""
    idx = peer_html.find("async function unwrapIdentity")
    snippet = peer_html[idx:idx + 2500]
    assert '"wrong passphrase or authenticated data"' in snippet


# ───────── unlock UX ────────────────────────────────────────────────

def test_unlock_card_present(peer_html: str):
    assert 'id="unlock-card"' in peer_html
    assert 'id="unlock-passphrase"' in peer_html
    assert 'id="btn-unlock"' in peer_html
    assert 'id="unlock-status"' in peer_html


def test_unlock_card_uses_password_input(peer_html: str):
    """The passphrase input MUST be type=password so it doesn't
    show on screen. autocomplete='current-password' lets password
    managers offer to fill."""
    idx = peer_html.find('id="unlock-passphrase"')
    open_start = peer_html.rfind("<input", 0, idx)
    open_end = peer_html.find(">", idx)
    tag = peer_html[open_start:open_end + 1]
    assert 'type="password"' in tag
    assert 'autocomplete="current-password"' in tag


def test_unlock_handler_present(peer_html: str):
    assert "async function _runUnlockFromInput()" in peer_html


def test_unlock_disables_button_during_kdf(peer_html: str):
    """Disable the unlock button during memory-hard derivation."""
    idx = peer_html.find("async function _runUnlockFromInput")
    snippet = peer_html[idx:idx + 2000]
    assert "btn.disabled = true" in snippet
    assert "btn.disabled = false" in snippet


def test_unlock_supports_enter_keydown(peer_html: str):
    """Phones especially benefit from Enter-to-submit — the user
    types passphrase, taps Done, expects unlock to fire. The
    handler MUST listen on the input's keydown."""
    idx = peer_html.find("$(\"#unlock-passphrase\")?.addEventListener(\"keydown\"")
    assert idx > 0
    snippet = peer_html[idx:idx + 300]
    assert '"Enter"' in snippet


def test_boot_stops_at_unlock_gate(peer_html: str):
    """If the on-disk record is a wrapped envelope, boot MUST NOT
    proceed to "ready" state. It shows the unlock gate and
    returns; nothing else fires until unlock succeeds."""
    idx = peer_html.find("async function boot()")
    snippet = peer_html[idx:idx + 4000]
    assert "isWrappedEnvelope(onDisk)" in snippet
    assert "_showUnlockGate(onDisk)" in snippet
    # Boot must `return` after showing the gate.
    gate_idx = snippet.find("_showUnlockGate(onDisk)")
    return_idx = snippet.find("return", gate_idx)
    assert return_idx > gate_idx
    assert return_idx - gate_idx < 200  # within a few statements


# ───────── setup / rotation / no-downgrade wiring ───────────────────

def test_set_passphrase_button_present(peer_html: str):
    assert 'id="btn-set-passphrase"' in peer_html


def test_set_passphrase_requires_double_entry(peer_html: str):
    """Two prompts — set + confirm. Standard pattern; without it a
    typo silently locks the user out of their identity forever."""
    idx = peer_html.find('"#btn-set-passphrase")?.addEventListener')
    snippet = peer_html[idx:idx + 2500]
    # Two prompt() calls.
    assert snippet.count("prompt(") >= 2
    # Mismatch warning.
    assert "don't match" in snippet


def test_set_passphrase_enforces_min_length(peer_html: str):
    idx = peer_html.find('"#btn-set-passphrase")?.addEventListener')
    snippet = peer_html[idx:idx + 2500]
    assert "pass1.length < IDENTITY_PASSPHRASE_MIN_CHARS" in snippet


def test_plaintext_downgrade_button_is_absent(peer_html: str):
    assert 'id="btn-remove-passphrase"' not in peer_html


def test_storage_api_refuses_plaintext_commit(peer_html: str):
    idx = peer_html.find("async function writeIdentity(rec)")
    snippet = peer_html[idx:idx + 900]
    assert "if (!isWrappedEnvelope(rec))" in snippet
    assert "refusing to commit browser private-key material without encryption" in snippet


def test_rotation_uses_compare_and_swap(peer_html: str):
    idx = peer_html.find('"#btn-set-passphrase")?.addEventListener')
    snippet = peer_html[idx:idx + 2600]
    assert "const expected = state.envelope" in snippet
    assert "_replaceIdentityAuthority(expected, replacement)" in snippet


def test_set_passphrase_relabels_to_change_on_rotation(peer_html: str):
    """If identity is already wrapped and the user clicks "Set",
    the button label MUST flip to "Change passphrase" so the user
    knows they're rotating, not creating fresh."""
    idx = peer_html.find("function _renderIdentityCard")
    snippet = peer_html[idx:idx + 2500]
    assert '"Change passphrase"' in snippet


# ───────── test surface ─────────────────────────────────────────────

def test_test_surface_exposes_wrap_helpers(peer_html: str):
    """Future ships + tests rely on this surface. Pin so a refactor
    can't quietly remove the hooks."""
    idx = peer_html.find("window.__oneLinkPeer")
    snippet = peer_html[idx:idx + 2000]
    for name in (
        "wrapIdentity",
        "unwrapIdentity",
        "isWrappedEnvelope",
        "_unlockWith",
        "state",
    ):
        assert name in snippet, f"test surface missing {name}"


def test_version_pin_bumped(peer_html: str):
    """The peer JS surface advertises a semver. Forward-compat:
    pin shape, not literal."""
    import re
    m = re.search(r"version:\s*['\"]\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?['\"]", peer_html)
    assert m


def test_page_version_matches_package():
    from one_link import __version__

    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html
