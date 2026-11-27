  // ── identity generation ─────────────────────────────────────────────
  async function generateIdentity() {
    let pubBytes;
    let privateJwk;
    try {
      const kp = await crypto.subtle.generateKey(
        { name: "Ed25519" },
        /*extractable=*/true,
        ["sign", "verify"],
      );
      const publicSpki = await crypto.subtle.exportKey(
        "raw", kp.publicKey,
      ).catch(async (error) => {
        if (!_isEd25519Unsupported(error)) throw error;
        return crypto.subtle.exportKey("spki", kp.publicKey);
      });
      // Raw is 32 bytes. Legacy engines that expose only SPKI wrap it in
      // the fixed Ed25519 SubjectPublicKeyInfo prefix and end in those bytes.
      if (publicSpki.byteLength !== 32 && publicSpki.byteLength !== 44) {
        throw new IdentityStorageError("Web Crypto returned an invalid Ed25519 key");
      }
      pubBytes = (publicSpki.byteLength === 32)
        ? new Uint8Array(publicSpki)
        : new Uint8Array(publicSpki).slice(-32);
      privateJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    } catch (error) {
      if (!_isEd25519Unsupported(error)) throw error;
      const seed = crypto.getRandomValues(new Uint8Array(32));
      try {
        pubBytes = await _wasmEd25519PublicFromSeed(seed);
        privateJwk = {
          kty: "OKP",
          crv: "Ed25519",
          d: bytesToB64Url(seed),
          x: bytesToB64Url(pubBytes),
          ext: true,
          key_ops: ["sign"],
        };
      } finally {
        seed.fill(0);
      }
    }
    try {
      const rec = {
        v: 1,
        alg: "Ed25519",
        created_ms: Date.now(),
        private_key_jwk: privateJwk,
        public_key_b64u: bytesToB64Url(pubBytes),
        fingerprint: await fingerprintOf(pubBytes),
      };
      await validatePlainIdentityRecord(rec);
      return rec;
    } finally {
      if (pubBytes) pubBytes.fill(0);
    }
  }

