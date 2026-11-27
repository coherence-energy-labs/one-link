  function _isNotFoundError(error) {
    return !!(error && error.name === "NotFoundError");
  }

  function _isPlainObject(value) {
    return !!value && typeof value === "object" && !Array.isArray(value);
  }

  function _assertExactKeys(value, expected, label) {
    if (!_isPlainObject(value)) {
      throw new IdentityCorruptionError(`${label} must be an object`);
    }
    const actual = Object.keys(value).sort();
    const wanted = [...expected].sort();
    if (actual.length !== wanted.length ||
        actual.some((key, index) => key !== wanted[index])) {
      throw new IdentityCorruptionError(`${label} has an unsupported schema`);
    }
  }

  function _decodeCanonicalB64Url(value, label, expectedLength = null) {
    if (typeof value !== "string" || value.length === 0 ||
        value.length > IDENTITY_FILE_MAX_BYTES * 2 ||
        value.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(value)) {
      throw new IdentityCorruptionError(`${label} is not canonical base64url`);
    }
    let decoded;
    try {
      decoded = b64UrlToBytes(value);
    } catch (error) {
      throw new IdentityCorruptionError(`${label} is not valid base64url`, error);
    }
    if (bytesToB64Url(decoded) !== value) {
      throw new IdentityCorruptionError(`${label} is not canonical base64url`);
    }
    if (expectedLength !== null && decoded.byteLength !== expectedLength) {
      throw new IdentityCorruptionError(
        `${label} must decode to ${expectedLength} bytes`,
      );
    }
    return decoded;
  }

  function _assertIdentityTimestamp(value, label) {
    if (!Number.isSafeInteger(value) || value <= 0 ||
        value > IDENTITY_CLOCK_MAX_MS) {
      throw new IdentityCorruptionError(`${label} is not a valid timestamp`);
    }
  }

  async function _validatePublicIdentityFields(rec, label) {
    const publicBytes = _decodeCanonicalB64Url(
      rec.public_key_b64u, `${label}.public_key_b64u`, 32,
    );
    if (typeof rec.fingerprint !== "string" ||
        !/^sha256:[0-9a-f]{64}$/.test(rec.fingerprint)) {
      throw new IdentityCorruptionError(`${label}.fingerprint is invalid`);
    }
    const expectedFingerprint = await fingerprintOf(publicBytes);
    if (expectedFingerprint !== rec.fingerprint) {
      throw new IdentityCorruptionError(
        `${label}.fingerprint does not match the public key`,
      );
    }
    return publicBytes;
  }

  async function validatePlainIdentityRecord(rec) {
    _assertExactKeys(
      rec,
      ["alg", "created_ms", "fingerprint", "private_key_jwk",
       "public_key_b64u", "v"],
      "identity record",
    );
    if (rec.v !== 1 || rec.alg !== "Ed25519") {
      throw new IdentityCorruptionError("identity algorithm/version is unsupported");
    }
    _assertIdentityTimestamp(rec.created_ms, "identity.created_ms");
    const publicBytes = await _validatePublicIdentityFields(rec, "identity");

    const jwk = rec.private_key_jwk;
    if (!_isPlainObject(jwk)) {
      throw new IdentityCorruptionError("identity.private_key_jwk must be an object");
    }
    const allowedJwkKeys = new Set([
      "alg", "crv", "d", "ext", "key_ops", "kty", "use", "x",
    ]);
    if (Object.keys(jwk).some((key) => !allowedJwkKeys.has(key)) ||
        jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
      throw new IdentityCorruptionError("identity private JWK schema is invalid");
    }
    const privateSeed = _decodeCanonicalB64Url(
      jwk.d, "identity.private_key_jwk.d", 32,
    );
    const jwkPublic = _decodeCanonicalB64Url(
      jwk.x, "identity.private_key_jwk.x", 32,
    );
    if (bytesToB64Url(jwkPublic) !== rec.public_key_b64u) {
      throw new IdentityCorruptionError(
        "identity private JWK does not claim the stored public key",
      );
    }
    if (jwk.key_ops !== undefined &&
        (!Array.isArray(jwk.key_ops) || jwk.key_ops.length !== 1 ||
         jwk.key_ops[0] !== "sign")) {
      throw new IdentityCorruptionError("identity private JWK key_ops is invalid");
    }

    const probe = new TextEncoder().encode(
      "one-link/browser-identity-validation/v1",
    );
    let signature = null;
    try {
      try {
        const privateKey = await crypto.subtle.importKey(
          "jwk", jwk, { name: "Ed25519" }, false, ["sign"],
        );
        const publicKey = await crypto.subtle.importKey(
          "raw", publicBytes, { name: "Ed25519" }, false, ["verify"],
        );
        signature = new Uint8Array(await crypto.subtle.sign(
          { name: "Ed25519" }, privateKey, probe,
        ));
        if (!await crypto.subtle.verify(
          { name: "Ed25519" }, publicKey, signature, probe,
        )) {
          throw new Error("signature verification failed");
        }
      } catch (error) {
        if (!_isEd25519Unsupported(error)) throw error;
        const derivedPublic = await _wasmEd25519PublicFromSeed(privateSeed);
        try {
          if (bytesToB64Url(derivedPublic) !== rec.public_key_b64u) {
            throw new Error("fallback public derivation does not match");
          }
        } finally {
          derivedPublic.fill(0);
        }
        signature = await _wasmEd25519Sign(privateSeed, probe);
        if (!await _wasmEd25519Verify(publicBytes, signature, probe)) {
          throw new Error("fallback signature verification failed");
        }
      }
    } catch (error) {
      throw new IdentityCorruptionError(
        "identity private key does not match the stored public key", error,
      );
    } finally {
      privateSeed.fill(0);
      probe.fill(0);
      if (signature) signature.fill(0);
    }
    return rec;
  }

  async function _validateLegacyWrappedIdentityEnvelope(rec) {
    _assertExactKeys(
      rec,
      ["created_ms", "ct_b64u", "fingerprint", "iv_b64u", "kdf",
       "kdf_iterations", "kdf_salt_b64u", "public_key_b64u", "v",
       "wrapped", "wrapped_ms"],
      "identity envelope",
    );
    if (rec.v !== 1 || rec.wrapped !== true ||
        rec.kdf !== "pbkdf2-sha256") {
      throw new IdentityCorruptionError("identity envelope KDF/version is unsupported");
    }
    if (!Number.isSafeInteger(rec.kdf_iterations) ||
        rec.kdf_iterations < 600000 || rec.kdf_iterations > 10000000) {
      throw new IdentityCorruptionError("identity envelope KDF cost is invalid");
    }
    _assertIdentityTimestamp(rec.created_ms, "identity.created_ms");
    _assertIdentityTimestamp(rec.wrapped_ms, "identity.wrapped_ms");
    await _validatePublicIdentityFields(rec, "identity envelope");
    _decodeCanonicalB64Url(
      rec.kdf_salt_b64u, "identity envelope salt", IDENTITY_SALT_BYTES,
    );
    _decodeCanonicalB64Url(rec.iv_b64u, "identity envelope IV", IDENTITY_IV_BYTES);
    const ciphertext = _decodeCanonicalB64Url(
      rec.ct_b64u, "identity envelope ciphertext",
    );
    if (ciphertext.byteLength < 17 ||
        ciphertext.byteLength > IDENTITY_FILE_MAX_BYTES) {
      throw new IdentityCorruptionError("identity envelope ciphertext size is invalid");
    }
    return rec;
  }

  async function _validateArgonWrappedIdentityEnvelope(rec) {
    _assertExactKeys(
      rec,
      ["aad_v", "cipher", "created_ms", "ct_b64u", "fingerprint",
       "iv_b64u", "kdf", "kdf_memory_kib", "kdf_parallelism",
       "kdf_salt_b64u", "kdf_time_cost", "public_key_b64u", "v",
       "wrapped", "wrapped_ms"],
      "identity envelope",
    );
    if (rec.v !== 2 || rec.wrapped !== true || rec.aad_v !== 1 ||
        rec.cipher !== "aes-256-gcm" || rec.kdf !== "argon2id-v19") {
      throw new IdentityCorruptionError(
        "identity envelope algorithm/version is unsupported",
      );
    }
    // Exact, non-negotiable parameters prevent a modified envelope from
    // forcing weak derivation or attacker-selected memory allocation.
    if (rec.kdf_memory_kib !== IDENTITY_ARGON_MEMORY_KIB ||
        rec.kdf_time_cost !== IDENTITY_ARGON_TIME_COST ||
        rec.kdf_parallelism !== IDENTITY_ARGON_PARALLELISM) {
      throw new IdentityCorruptionError("identity envelope KDF profile is invalid");
    }
    _assertIdentityTimestamp(rec.created_ms, "identity.created_ms");
    _assertIdentityTimestamp(rec.wrapped_ms, "identity.wrapped_ms");
    await _validatePublicIdentityFields(rec, "identity envelope");
    _decodeCanonicalB64Url(
      rec.kdf_salt_b64u, "identity envelope salt", IDENTITY_SALT_BYTES,
    );
    _decodeCanonicalB64Url(
      rec.iv_b64u, "identity envelope IV", IDENTITY_IV_BYTES,
    );
    const ciphertext = _decodeCanonicalB64Url(
      rec.ct_b64u, "identity envelope ciphertext",
    );
    if (ciphertext.byteLength < 17 ||
        ciphertext.byteLength > IDENTITY_FILE_MAX_BYTES) {
      throw new IdentityCorruptionError("identity envelope ciphertext size is invalid");
    }
    return rec;
  }

  async function validateWrappedIdentityEnvelope(rec) {
    if (!_isPlainObject(rec)) {
      throw new IdentityCorruptionError("identity envelope must be an object");
    }
    if (rec.v === 1) return _validateLegacyWrappedIdentityEnvelope(rec);
    if (rec.v === 2) return _validateArgonWrappedIdentityEnvelope(rec);
    throw new IdentityCorruptionError("identity envelope version is unsupported");
  }

  async function validateIdentityObject(rec) {
    if (_isPlainObject(rec) && rec.wrapped === true) {
      return validateWrappedIdentityEnvelope(rec);
    }
    return validatePlainIdentityRecord(rec);
  }

