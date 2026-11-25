  function _identityEnvelopeAad(envelope) {
    const header = {
      aad_v: envelope.aad_v,
      cipher: envelope.cipher,
      created_ms: envelope.created_ms,
      fingerprint: envelope.fingerprint,
      iv_b64u: envelope.iv_b64u,
      kdf: envelope.kdf,
      kdf_memory_kib: envelope.kdf_memory_kib,
      kdf_parallelism: envelope.kdf_parallelism,
      kdf_salt_b64u: envelope.kdf_salt_b64u,
      kdf_time_cost: envelope.kdf_time_cost,
      public_key_b64u: envelope.public_key_b64u,
      v: envelope.v,
      wrapped: envelope.wrapped,
      wrapped_ms: envelope.wrapped_ms,
    };
    return new TextEncoder().encode(
      `one-link/browser-identity-envelope/v2\n${_canonicalJson(header)}`,
    );
  }

  async function _wrapIdentityV2(rec, passphrase, minimumChars) {
    await validatePlainIdentityRecord(rec);
    const salt = _randomBytes(IDENTITY_SALT_BYTES);
    const iv = _randomBytes(IDENTITY_IV_BYTES);
    const envelope = {
      v: 2,
      wrapped: true,
      aad_v: 1,
      cipher: "aes-256-gcm",
      kdf: "argon2id-v19",
      kdf_memory_kib: IDENTITY_ARGON_MEMORY_KIB,
      kdf_time_cost: IDENTITY_ARGON_TIME_COST,
      kdf_parallelism: IDENTITY_ARGON_PARALLELISM,
      kdf_salt_b64u: bytesToB64Url(salt),
      iv_b64u: bytesToB64Url(iv),
      ct_b64u: "",
      fingerprint: rec.fingerprint,
      public_key_b64u: rec.public_key_b64u,
      created_ms: rec.created_ms,
      wrapped_ms: Date.now(),
    };
    const key = await _deriveArgonAesKey(passphrase, salt, minimumChars);
    const plaintext = new TextEncoder().encode(JSON.stringify(rec));
    try {
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: _identityEnvelopeAad(envelope) },
        key,
        plaintext,
      );
      envelope.ct_b64u = bytesToB64Url(new Uint8Array(ciphertext));
      await validateWrappedIdentityEnvelope(envelope);
      return envelope;
    } finally {
      plaintext.fill(0);
      salt.fill(0);
      iv.fill(0);
    }
  }

  async function wrapIdentity(rec, passphrase) {
    return _wrapIdentityV2(rec, passphrase, IDENTITY_PASSPHRASE_MIN_CHARS);
  }

  async function _unwrapLegacyIdentity(envelope, passphrase) {
    const salt = _decodeCanonicalB64Url(
      envelope.kdf_salt_b64u, "identity envelope salt", IDENTITY_SALT_BYTES,
    );
    const iv = _decodeCanonicalB64Url(
      envelope.iv_b64u, "identity envelope IV", IDENTITY_IV_BYTES,
    );
    const ciphertext = _decodeCanonicalB64Url(
      envelope.ct_b64u, "identity envelope ciphertext",
    );
    const key = await _deriveLegacyAesKey(
      passphrase, salt, envelope.kdf_iterations,
    );
    return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  }

  async function _unwrapArgonIdentity(envelope, passphrase) {
    const salt = _decodeCanonicalB64Url(
      envelope.kdf_salt_b64u, "identity envelope salt", IDENTITY_SALT_BYTES,
    );
    const iv = _decodeCanonicalB64Url(
      envelope.iv_b64u, "identity envelope IV", IDENTITY_IV_BYTES,
    );
    const ciphertext = _decodeCanonicalB64Url(
      envelope.ct_b64u, "identity envelope ciphertext",
    );
    const key = await _deriveArgonAesKey(passphrase, salt, 1);
    return crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: _identityEnvelopeAad(envelope) },
      key,
      ciphertext,
    );
  }

  async function unwrapIdentity(envelope, passphrase) {
    await validateWrappedIdentityEnvelope(envelope);
    let plaintext;
    try {
      plaintext = envelope.v === 1
        ? await _unwrapLegacyIdentity(envelope, passphrase)
        : await _unwrapArgonIdentity(envelope, passphrase);
    } catch (error) {
      if (error instanceof IdentityCorruptionError ||
          error instanceof IdentityKdfError) throw error;
      throw new IdentityKdfError("wrong passphrase or authenticated data", error);
    }
    let rec;
    try {
      const json = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
      rec = JSON.parse(json);
    } catch (error) {
      throw new IdentityCorruptionError(
        "decrypted identity is not valid JSON", error,
      );
    } finally {
      new Uint8Array(plaintext).fill(0);
    }
    await validatePlainIdentityRecord(rec);
    if (!_samePublicIdentity(rec, envelope)) {
      throw new IdentityCorruptionError(
        "encrypted identity does not match its public envelope",
      );
    }
    return rec;
  }

  function isWrappedEnvelope(rec) {
    return !!(rec && rec.wrapped === true &&
      (rec.v === 1 || rec.v === 2) && rec.ct_b64u);
  }

