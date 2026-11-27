  const { bytesToHex, bytesToB64Url, b64UrlToBytes } = createPeerEncoding({ btoa, atob });

  // ── fingerprint ─────────────────────────────────────────────────────
  // BLAKE3 isn't in browsers natively. The desktop daemon uses BLAKE3
  // for fingerprints; for browser-peer we tag the hash algorithm so a
  // future ship can vendor a BLAKE3-WASM and produce daemon-compatible
  // fingerprints. v0.16.0: SHA-256, prefixed `sha256:`.
  async function fingerprintOf(pubBytes) {
    const digest = await crypto.subtle.digest("SHA-256", pubBytes);
    return "sha256:" + bytesToHex(digest);
  }

