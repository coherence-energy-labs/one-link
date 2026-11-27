"""Encrypted-on-disk identity (PASSPHRASE_ENV)."""

from __future__ import annotations

from pathlib import Path

import pytest

from one_link.identity import PASSPHRASE_ENV, load_or_create


def test_unencrypted_create_then_load(tmp_path: Path, monkeypatch):
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    key = tmp_path / "id.key"
    a = load_or_create(key)
    b = load_or_create(key)
    assert a.fingerprint == b.fingerprint
    # On-disk format is unencrypted PEM
    raw = key.read_text()
    assert "BEGIN PRIVATE KEY" in raw  # unencrypted PKCS8


def test_encrypted_create_then_load_with_passphrase(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "correct horse battery staple")
    a = load_or_create(key)
    b = load_or_create(key)
    assert a.fingerprint == b.fingerprint
    raw = key.read_text()
    assert "ENCRYPTED PRIVATE KEY" in raw


def test_encrypted_load_with_wrong_passphrase_raises(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "secret-1")
    load_or_create(key)
    monkeypatch.setenv(PASSPHRASE_ENV, "secret-2-WRONG")
    with pytest.raises(RuntimeError, match="encrypted"):
        load_or_create(key)


def test_encrypted_load_with_no_passphrase_raises(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "secret")
    load_or_create(key)
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    with pytest.raises(RuntimeError, match="encrypted"):
        load_or_create(key)


def test_transparent_migration_unencrypted_to_encrypted(tmp_path: Path, monkeypatch):
    """If the file is unencrypted but PASSPHRASE_ENV is set on next launch,
    re-save the file encrypted."""
    key = tmp_path / "id.key"
    # Phase 1: create unencrypted
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    a = load_or_create(key)
    assert "BEGIN PRIVATE KEY" in key.read_text()

    # Phase 2: set passphrase, load again — file should be re-saved encrypted
    monkeypatch.setenv(PASSPHRASE_ENV, "new-passphrase")
    b = load_or_create(key)
    assert b.fingerprint == a.fingerprint
    assert "ENCRYPTED PRIVATE KEY" in key.read_text()


def test_explicit_passphrase_arg_overrides_env(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "env-pass")
    a = load_or_create(key, passphrase="explicit-pass")
    # Env passphrase should NOT decrypt; explicit one must.
    monkeypatch.setenv(PASSPHRASE_ENV, "env-pass")  # still set
    with pytest.raises(RuntimeError):
        load_or_create(key)  # uses env passphrase, fails
    b = load_or_create(key, passphrase="explicit-pass")
    assert a.fingerprint == b.fingerprint


# ─── sealed form: scrypt + ChaCha20-Poly1305 ────────────────────────

import base64  # noqa: E402

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from one_link import identity as identity_module  # noqa: E402
from one_link.passphrase_source import (  # noqa: E402
    FILE_ENV_VAR,
    PassphraseSourceError,
    adopt_passphrase_file,
)


def _sealed_fields(path: Path) -> tuple[bytes, bytes]:
    text = path.read_bytes().strip()
    assert text.startswith(identity_module._SEALED_BEGIN)
    raw = base64.b64decode(
        text[len(identity_module._SEALED_BEGIN) : -len(identity_module._SEALED_END)]
    )
    return raw[: identity_module._SEALED_HEADER_LEN], raw


def _armor(edge: str, label: str) -> bytes:
    """A PEM armor line, spelled independently of the module under test.

    In parts on purpose: a literal armor pair in source reads to the secret
    scan as a private key.
    """
    return b"-" * 5 + edge.encode() + b" " + label.encode() + b"-" * 5


_LEGACY_BEGIN = _armor("BEGIN", "ENCRYPTED PRIVATE KEY")


def test_sealed_key_file_is_exactly_the_documented_armor(tmp_path: Path, monkeypatch):
    """The file layout is a compatibility surface: a key sealed by this
    release has to open in every later one. The bytes are pinned here, not
    read back from the constants that wrote them."""
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "pw")
    load_or_create(key)
    blob = key.read_bytes()
    lines = blob.split(b"\n")
    assert lines[0] == _armor("BEGIN", "ONE LINK ENCRYPTED PRIVATE KEY")
    assert lines[-2] == _armor("END", "ONE LINK ENCRYPTED PRIVATE KEY")
    assert lines[-1] == b"", "the file ends with one newline"
    raw = base64.b64decode(b"".join(lines[1:-2]), validate=True)
    assert raw[:5] == b"OLIK\x01"
    assert identity_module.key_file_protection(blob) == identity_module.PROTECTION_SEALED
    # The markers the module compares against are the same bytes.
    assert identity_module._SEALED_BEGIN == lines[0]
    assert identity_module._SEALED_END == lines[-2]
    assert identity_module._LEGACY_ENCRYPTED_BEGIN == _LEGACY_BEGIN


def test_new_encrypted_key_is_sealed_with_a_memory_hard_kdf(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "correct horse battery staple")
    load_or_create(key)
    header, _raw = _sealed_fields(key)
    magic = identity_module._SEALED_MAGIC
    assert header.startswith(magic)
    kdf, log2_n, r, p = header[len(magic) : len(magic) + 4]
    # scrypt at the same cost as the lockbox: 128 * 2^17 * 8 bytes per guess.
    assert (kdf, log2_n, r, p) == (1, 17, 8, 1)
    # The old PKCS#8 encryption, with its 2,048 PBKDF2 rounds, is not written.
    assert _LEGACY_BEGIN not in key.read_bytes()


def test_legacy_pbkdf2_key_loads_and_is_resealed(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    priv = Ed25519PrivateKey.generate()
    key.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"old-pass"),
        )
    )
    assert key.read_bytes().startswith(_LEGACY_BEGIN + b"\n")
    monkeypatch.setenv(PASSPHRASE_ENV, "old-pass")
    loaded = load_or_create(key)
    assert loaded.private.private_bytes_raw() == priv.private_bytes_raw()
    # Same passphrase, same key, stronger wrapping.
    _sealed_fields(key)
    again = load_or_create(key)
    assert again.fingerprint == loaded.fingerprint


def test_legacy_pbkdf2_key_with_wrong_passphrase_is_left_alone(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    priv = Ed25519PrivateKey.generate()
    original = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"old-pass"),
    )
    key.write_bytes(original)
    monkeypatch.setenv(PASSPHRASE_ENV, "not-it")
    with pytest.raises(RuntimeError, match="encrypted"):
        load_or_create(key)
    assert key.read_bytes() == original


def _rewrite_sealed(path: Path, mutate) -> None:
    _header, raw = _sealed_fields(path)
    body = base64.encodebytes(bytes(mutate(bytearray(raw))))
    path.write_bytes(
        identity_module._SEALED_BEGIN + b"\n" + body + identity_module._SEALED_END + b"\n"
    )


def test_weakened_kdf_parameters_are_refused(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "pw")
    load_or_create(key)
    offset = len(identity_module._SEALED_MAGIC) + 1

    def weaken(raw: bytearray) -> bytearray:
        raw[offset] = 10  # N = 2^10
        return raw

    _rewrite_sealed(key, weaken)
    with pytest.raises(RuntimeError, match="unsupported KDF parameters"):
        load_or_create(key)


def test_oversized_kdf_parameters_are_refused_before_any_work(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "pw")
    load_or_create(key)
    offset = len(identity_module._SEALED_MAGIC) + 1

    def inflate(raw: bytearray) -> bytearray:
        raw[offset] = 30  # would ask scrypt for a terabyte
        return raw

    _rewrite_sealed(key, inflate)
    monkeypatch.setattr(
        identity_module, "_sealed_key", lambda *a: pytest.fail("KDF must not run")
    )
    with pytest.raises(RuntimeError, match="unsupported KDF parameters"):
        load_or_create(key)


def test_header_is_authenticated(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "pw")
    load_or_create(key)

    def flip_salt(raw: bytearray) -> bytearray:
        raw[identity_module._SEALED_HEADER_LEN - 1] ^= 0x01
        return raw

    _rewrite_sealed(key, flip_salt)
    with pytest.raises(RuntimeError, match="encrypted"):
        load_or_create(key)


def test_truncated_sealed_key_is_refused(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "pw")
    load_or_create(key)
    key.write_bytes(key.read_bytes()[:80])
    with pytest.raises(RuntimeError, match="encrypted"):
        load_or_create(key)


# ─── passphrase from a file ─────────────────────────────────────────


def test_passphrase_file_is_adopted(tmp_path: Path):
    secret = tmp_path / "pw"
    secret.write_text("from-a-file\n")
    secret.chmod(0o600)
    env = {FILE_ENV_VAR: str(secret)}
    assert adopt_passphrase_file(env) is True
    assert env[PASSPHRASE_ENV] == "from-a-file"
    assert adopt_passphrase_file(env) is True  # idempotent


def test_identity_key_can_be_sealed_from_a_passphrase_file(tmp_path: Path, monkeypatch):
    secret = tmp_path / "pw"
    secret.write_text("file-secret")
    secret.chmod(0o600)
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    monkeypatch.setenv(FILE_ENV_VAR, str(secret))
    key = tmp_path / "id.key"
    created = load_or_create(key)
    _sealed_fields(key)
    monkeypatch.delenv(FILE_ENV_VAR)
    monkeypatch.setenv(PASSPHRASE_ENV, "file-secret")
    assert load_or_create(key).fingerprint == created.fingerprint


def test_no_passphrase_file_means_no_change():
    env: dict[str, str] = {}
    assert adopt_passphrase_file(env) is False
    assert env == {}


@pytest.mark.parametrize(
    "content, problem",
    [(b"", "empty"), (b"\n", "empty"), (b"\xff\xfe", "UTF-8"), (b"a\x00b", "NUL")],
)
def test_unusable_passphrase_file_is_an_error(tmp_path: Path, content, problem):
    secret = tmp_path / "pw"
    secret.write_bytes(content)
    secret.chmod(0o600)
    with pytest.raises(PassphraseSourceError, match=problem):
        adopt_passphrase_file({FILE_ENV_VAR: str(secret)})


def test_missing_passphrase_file_is_an_error(tmp_path: Path):
    with pytest.raises(PassphraseSourceError, match="cannot be read"):
        adopt_passphrase_file({FILE_ENV_VAR: str(tmp_path / "absent")})


def test_passphrase_file_and_variable_must_agree(tmp_path: Path):
    secret = tmp_path / "pw"
    secret.write_text("one")
    secret.chmod(0o600)
    with pytest.raises(PassphraseSourceError, match="disagree"):
        adopt_passphrase_file({FILE_ENV_VAR: str(secret), PASSPHRASE_ENV: "two"})


@pytest.mark.skipif(not hasattr(Path, "chmod") or __import__("os").name != "posix",
                    reason="POSIX permission bits")
def test_passphrase_file_others_can_write_is_refused(tmp_path: Path):
    secret = tmp_path / "pw"
    secret.write_text("x")
    secret.chmod(0o666)
    with pytest.raises(PassphraseSourceError, match="writable by other users"):
        adopt_passphrase_file({FILE_ENV_VAR: str(secret)})


# ─── the security report says how the key is protected ──────────────


def test_security_report_describes_identity_key_protection(tmp_path: Path, monkeypatch):
    from one_link import hardening_checks

    key = tmp_path / "id.key"
    assert hardening_checks.check_identity_key_protection(key) == []

    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    load_or_create(key)
    (plain,) = hardening_checks.check_identity_key_protection(key)
    assert plain.severity == "warn" and "unencrypted" in plain.message

    monkeypatch.setenv(PASSPHRASE_ENV, "pw")
    load_or_create(key)
    (sealed,) = hardening_checks.check_identity_key_protection(key)
    assert sealed.severity == "info" and "sealed" in sealed.message

    key.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"pw"),
        )
    )
    (legacy,) = hardening_checks.check_identity_key_protection(key)
    assert legacy.severity == "warn" and "PBKDF2" in legacy.message
