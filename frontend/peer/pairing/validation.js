  function _validatePairTimestamp(value, label) {
    if (!Number.isSafeInteger(value) || value < 0 ||
        Math.abs(Date.now() - value) > PAIR_CLOCK_SKEW_MS) {
      throw new Error(`${label} timestamp is invalid or expired`);
    }
    return value;
  }

  function _pairMessageWithinSizeBound(envelope, label) {
    const size = new TextEncoder().encode(_canonicalJson(envelope)).byteLength;
    if (size > PAIR_MESSAGE_MAX_CHARS) {
      throw new Error(`${label} exceeds the protocol size limit`);
    }
  }

  async function _validatePairHello(envelope) {
    _requireExactKeys(
      envelope,
      ["fingerprint", "nonce", "pubkey", "t", "ts", "v"],
      ["alias"],
      "pair hello",
    );
    _pairMessageWithinSizeBound(envelope, "pair hello");
    if (envelope.v !== PAIR_PROTOCOL_VERSION || envelope.t !== "hello") {
      throw new Error("pair hello has the wrong protocol version or type");
    }
    _validatePairTimestamp(envelope.ts, "pair hello");
    const binding = await _validatePeerBinding(
      envelope.fingerprint, envelope.pubkey, "pair hello",
    );
    const nonceBytes = _canonicalB64UrlBytes(
      envelope.nonce, PAIR_NONCE_BYTES, "pair hello nonce",
    );
    const alias = envelope.alias === undefined ? "" : envelope.alias;
    if (typeof alias !== "string" || alias.length > PAIR_ALIAS_MAX_CHARS ||
        /[\u0000-\u001f\u007f]/.test(alias)) {
      throw new Error("pair hello alias is invalid or too large");
    }
    const normalized = {
      v: PAIR_PROTOCOL_VERSION,
      t: "hello",
      pubkey: binding.public_key_b64u,
      fingerprint: binding.fingerprint,
      nonce: bytesToB64Url(nonceBytes),
      ts: envelope.ts,
    };
    if (alias) normalized.alias = alias;
    return normalized;
  }

  function _validatePairConfirm(envelope) {
    _requireExactKeys(
      envelope,
      ["fingerprint", "matched", "t", "ts", "v"],
      [],
      "pair confirmation",
    );
    _pairMessageWithinSizeBound(envelope, "pair confirmation");
    if (envelope.v !== PAIR_PROTOCOL_VERSION || envelope.t !== "confirm") {
      throw new Error("pair confirmation has the wrong protocol version or type");
    }
    _canonicalSha256Fingerprint(envelope.fingerprint, "pair confirmation fingerprint");
    _validatePairTimestamp(envelope.ts, "pair confirmation");
    if (typeof envelope.matched !== "boolean") {
      throw new Error("pair confirmation matched flag must be boolean");
    }
    return envelope;
  }

  // Pair-session lifecycle. Per WebRTC session at most one pair
  // attempt runs. `pairing` is mutually-driven state that closes
  // out either by both-confirm or by mismatch / timeout / disconnect.
