  // ── v0.17.0 — Rendezvous client ─────────────────────────────────────
  //
  // Wire-format compat with desktop daemon's rendezvous_proto:
  //   - PROTOCOL_VERSION = "OL-RDZ-1"
  //   - canonical signing form: JSON.stringify with sorted keys,
  //     separators ",", ":", ASCII-only (no Unicode escape-passthrough)
  //   - signature: Ed25519 over canonical bytes of the dict MINUS
  //     the "signature" field
  //   - register endpoint: POST <rdzUrl>/api/v1/register, body is
  //     the wire dict {v, type, pubkey_b64, timestamp_ms, ttl_s,
  //     advertised_endpoints, nat_type, capabilities, signature}
  //   - lookup endpoint: GET <rdzUrl>/api/v1/lookup/<pubkey_b64>
  const RDZ_PROTOCOL_VERSION = "OL-RDZ-1";
  const RDZ_DEFAULT_TTL_S = 300;
  const RDZ_MAX_TTL_MS = 24 * 60 * 60 * 1000;
  const RDZ_REFRESH_MARGIN_MS = 30 * 1000; // re-register 30s before expiry
  const RDZ_FETCH_TIMEOUT_MS = 10 * 1000;
  const RDZ_RESPONSE_MAX_BYTES = 32 * 1024;
  const RDZ_REGISTER_ACK_KEYS = Object.freeze([
    "expires_at_ms", "observed_host", "observed_port", "server_time_ms", "type", "v",
  ]);
  const RDZ_LOOKUP_ACK_KEYS = Object.freeze([
    "advertised_endpoints", "capabilities", "expires_at_ms", "nat_type",
    "observed_endpoint", "pubkey_b64", "server_time_ms", "type", "v",
  ]);

  // Canonical JSON: keys sorted, no spaces, ASCII-safe. Mirrors
  // Python `json.dumps(d, sort_keys=True, separators=(",", ":"),
  // ensure_ascii=True)` exactly. Used for both signing AND
  // verification, so any drift breaks every signature.
  function _canonicalJson(obj) {
    if (obj === null) return "null";
    if (typeof obj === "number") {
      // Python json.dumps emits integers without trailing zeros
      // and no scientific notation for typical ranges. Web JSON
      // matches for safe-int range; bail loudly outside.
      if (!Number.isFinite(obj)) {
        throw new Error("non-finite numbers aren't canonical-JSON-safe");
      }
      // Integers stringified the same in Python + JS for ints.
      // For floats: Python emits e.g. "1.5", JS emits "1.5". For
      // exotic floats they may diverge; we never sign floats.
      return Number.isInteger(obj) ? obj.toFixed(0) : String(obj);
    }
    if (typeof obj === "boolean") return obj ? "true" : "false";
    if (typeof obj === "string") {
      // Python ensure_ascii escapes any non-ASCII as \uXXXX.
      // JSON.stringify on a string also produces \uXXXX for
      // non-BMP chars but uses unescaped UTF-8 for BMP non-ASCII.
      // We force \u escaping for ALL non-ASCII to match Python.
      let out = '"';
      for (let i = 0; i < obj.length; i++) {
        const c = obj.charCodeAt(i);
        if (c === 0x22) out += '\\"';
        else if (c === 0x5c) out += "\\\\";
        else if (c === 0x08) out += "\\b";
        else if (c === 0x0c) out += "\\f";
        else if (c === 0x0a) out += "\\n";
        else if (c === 0x0d) out += "\\r";
        else if (c === 0x09) out += "\\t";
        else if (c < 0x20 || c >= 0x7f) {
          out += "\\u" + c.toString(16).padStart(4, "0");
        } else {
          out += obj[i];
        }
      }
      return out + '"';
    }
    if (Array.isArray(obj)) {
      return "[" + obj.map(_canonicalJson).join(",") + "]";
    }
    if (typeof obj === "object") {
      const keys = Object.keys(obj).sort();
      return "{" + keys.map((k) =>
        _canonicalJson(k) + ":" + _canonicalJson(obj[k])
      ).join(",") + "}";
    }
    throw new Error(`uncanonicalable type: ${typeof obj}`);
  }

  // Prefer native Web Crypto and use the integrity-pinned RustCrypto module
  // only when the browser explicitly reports Ed25519 as unsupported.
  async function _signEd25519(privateJwk, bytes) {
    const message = _copyBoundedBytes(
      bytes, "Ed25519 message", ED25519_WASM_MAX_MESSAGE_BYTES,
    );
    try {
      try {
        const key = await crypto.subtle.importKey(
          "jwk",
          privateJwk,
          { name: "Ed25519" },
          /*extractable=*/false,
          ["sign"],
        );
        const signature = new Uint8Array(await crypto.subtle.sign(
          { name: "Ed25519" }, key, message,
        ));
        if (signature.byteLength !== 64) {
          throw new IdentityStorageError("Web Crypto returned an invalid signature");
        }
        return signature;
      } catch (error) {
        if (!_isEd25519Unsupported(error)) throw error;
        const seed = _decodeCanonicalB64Url(
          privateJwk && privateJwk.d, "Ed25519 private JWK seed", 32,
        );
        try {
          return await _wasmEd25519Sign(seed, message);
        } finally {
          seed.fill(0);
        }
      }
    } finally {
      message.fill(0);
    }
  }

  // Verify Ed25519 signature for the lookup-result branch (we
  // verify peer registers we look up). Public key is 32 bytes raw.
  async function _verifyEd25519(pubkeyBytes, signature, message) {
    const publicKey = _copyBoundedBytes(
      pubkeyBytes, "Ed25519 public key", 32, 32,
    );
    const signatureBytes = _copyBoundedBytes(
      signature, "Ed25519 signature", 64, 64,
    );
    const messageBytes = _copyBoundedBytes(
      message, "Ed25519 message", ED25519_WASM_MAX_MESSAGE_BYTES,
    );
    try {
      try {
        const key = await crypto.subtle.importKey(
          "raw",
          publicKey,
          { name: "Ed25519" },
          /*extractable=*/false,
          ["verify"],
        );
        return await crypto.subtle.verify(
          { name: "Ed25519" }, key, signatureBytes, messageBytes,
        );
      } catch (error) {
        if (!_isEd25519Unsupported(error)) throw error;
        return await _wasmEd25519Verify(publicKey, signatureBytes, messageBytes);
      }
    } finally {
      publicKey.fill(0);
      signatureBytes.fill(0);
      messageBytes.fill(0);
    }
  }

  // v0.20.7 (security audit C1): pull the DTLS-SRTP fingerprint
  // out of an SDP blob. RFC 8122 a=fingerprint line. Mirrors
  // peer_rtc.py's _extract_dtls_fingerprint exactly so both
  // sides compute the same value from the same bytes.
  function _extractDtlsFingerprint(sdp) {
    if (typeof sdp !== "string") return "";
    const m = /^a=fingerprint:(\S+)\s+([0-9A-Fa-f:]+)/m.exec(sdp);
    if (!m) return "";
    return m[1].toLowerCase() + ":" + m[2].toUpperCase();
  }

  // v0.20.7 (security audit C1 + H6): verify a daemon-signed
  // peer-rtc answer envelope. Throws on any failure so the
  // caller's catch block surfaces the rejection to the UI
  // instead of silently applying a tampered SDP.
  // ``expectedFingerprint`` is the daemon_fingerprint the phone
  // pinned at QR-scan time. When provided, the verifier also
  // confirms the answer envelope claims the SAME fingerprint,
  // closing the audit-H6 gap where peer.html ignored the
  // ``&fp=`` field from the QR.
  async function _verifySignedDaemonAnswer(envelope, expectedFingerprint) {
    if (!envelope || envelope.t !== "answer") {
      throw new Error("answer envelope expected");
    }
    if (typeof envelope.signature !== "string" || !envelope.signature) {
      throw new Error(
        "daemon answer is not signed (peer outdated). Please " +
        "update the daemon to v0.20.7+ for MITM-resistant pairing."
      );
    }
    const sigB64u = envelope.signature;
    const pubB64u = envelope.daemon_pubkey_b64u;
    if (typeof pubB64u !== "string" || !pubB64u) {
      throw new Error("daemon answer is missing daemon_pubkey_b64u");
    }
    const claimedFingerprint = envelope.daemon_fingerprint || "";
    const claimedDtls = envelope.dtls_fingerprint || "";

    const pubBytes = b64UrlToBytes(pubB64u);
    if (!pubBytes || pubBytes.length !== 32) {
      throw new Error("daemon_pubkey_b64u is not 32 bytes");
    }
    // Fingerprint cross-check #1: daemon_fingerprint in the
    // envelope claims sha256:hex of pubBytes. Re-derive and
    // require equality.
    const derivedFp = await fingerprintOf(pubBytes);
    if (claimedFingerprint && claimedFingerprint !== derivedFp) {
      throw new Error(
        "daemon_fingerprint does not match sha256(daemon_pubkey)"
      );
    }
    // Fingerprint cross-check #2 (audit H6): the phone pinned
    // a daemon fingerprint at QR-scan time. The signed answer
    // envelope MUST claim that same fingerprint. A MITM serving
    // a different daemon's signed answer (with a valid sig
    // under THAT daemon's pubkey) would land here with a
    // different fingerprint and we refuse.
    if (expectedFingerprint &&
        claimedFingerprint &&
        expectedFingerprint !== claimedFingerprint) {
      throw new Error(
        "daemon answered with a different identity than the QR " +
        "pinned at pair time (possible MITM or wrong daemon)"
      );
    }
    // Build the canonical-bytes input for the signature: the
    // envelope minus the signature field, JSON-serialized with
    // sorted keys / no whitespace (matches peer_rtc._canonical).
    const signing = Object.assign({}, envelope);
    delete signing.signature;
    const canonical = _canonicalJson(signing);
    const enc = new TextEncoder();
    const sig = b64UrlToBytes(sigB64u);
    if (!sig || sig.length !== 64) {
      throw new Error("daemon answer signature is not 64 bytes");
    }
    const ok = await _verifyEd25519(pubBytes, sig, enc.encode(canonical));
    if (!ok) {
      throw new Error("daemon answer signature does not verify");
    }
    // Cross-check: the SDP's a=fingerprint must match the claim
    // the daemon cryptographically committed to. A MITM that
    // rewrites the SDP fingerprint to point at their own DTLS
    // cert invalidates this check.
    const sdpDtls = _extractDtlsFingerprint(envelope.sdp || "");
    if (claimedDtls) {
      if (!sdpDtls) {
        throw new Error(
          "answer SDP is missing a=fingerprint (DTLS binding broken)"
        );
      }
      if (sdpDtls !== claimedDtls) {
        throw new Error(
          "DTLS fingerprint in SDP does not match the daemon's " +
          "signed claim (possible MITM)"
        );
      }
    }
  }

  // Build a RegisterReq matching the desktop daemon wire format.
  // `advertised_endpoints` is a list of {host, port}. The browser
  // cannot accept an inbound TCP/UDP connection.  It therefore publishes an
  // empty route list. RegisterAck reports the HTTP request's source address for
  // diagnostics only; that ephemeral port must never be treated as dialable.
  //
  // Wire-format note on b64: despite the field name `pubkey_b64`,
  // the daemon's rendezvous_proto uses urlsafe_b64encode().rstrip("=")
  // — that's base64url WITHOUT padding. The JS bytesToB64Url helper
  // already produces this exact form, so we use the keypair's
  // public_key_b64u directly (no conversion). Same for the
  // signature output.
  async function _buildSignedRegister(rec, opts) {
    opts = opts || {};
    const ttl_s = opts.ttl_s || RDZ_DEFAULT_TTL_S;
    const advertised_endpoints = opts.advertised_endpoints || [];
    const nat_type = opts.nat_type || "unknown";
    // OL-RDZ-1 has one signed, bounded capability vector.  Keep transport
    // negotiation inside that existing field so older exact-schema parsers
    // can consume browser registrations.  A separate `transport_caps` field
    // was never part of the wire contract and made every live browser
    // registration fail before signature verification.
    const capabilities = opts.capabilities || browserTransportCapabilities();
    const signing = {
      v: RDZ_PROTOCOL_VERSION,
      type: "register",
      pubkey_b64: rec.public_key_b64u, // base64url, no padding
      timestamp_ms: Date.now(),
      ttl_s,
      advertised_endpoints: advertised_endpoints.map((e) => ({
        host: String(e.host),
        port: Number(e.port),
      })),
      nat_type,
      capabilities: capabilities.slice(),
    };
    const canonical = _canonicalJson(signing);
    const enc = new TextEncoder();
    const sig = await _signEd25519(rec.private_key_jwk, enc.encode(canonical));
    return Object.assign({}, signing, {
      signature: bytesToB64Url(sig), // base64url, no padding
    });
  }

