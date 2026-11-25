  // ── v0.18.0 — WebRTC DataChannel transport foundation ───────────────
  const WRTC_PROTOCOL_VERSION = "OL-WRTC-1";
  const WRTC_SIGNAL_TTL_MS = 5 * 60 * 1000;
  const WRTC_SIGNAL_MAX_BYTES = 2 * 1024 * 1024;
  const WRTC_SIGNAL_TEXT_MAX_CHARS = 3 * 1024 * 1024;
  const WRTC_SDP_MAX_CHARS = 1024 * 1024;
  const WRTC_ICE_CANDIDATE_MAX_CHARS = 16 * 1024;
  const ED25519_PUBLIC_KEY_BYTES = 32;
  const ED25519_SIGNATURE_BYTES = 64;
  const SHA256_FINGERPRINT_RE = /^sha256:[0-9a-f]{64}$/;
  const WRTC_SIGNAL_KEYS = Object.freeze([
    "body", "sender_pubkey_b64", "signature", "timestamp_ms", "type", "v",
  ]);
  // ICE policy is resolved by the daemon. Just Works may disclose community
  // STUN servers; Quiet/Off-grid and explicit opt-out return an empty list for
  // host-only LAN ICE. The browser never carries a hidden hard-coded provider.
  const WEBRTC_CONTROL_LABEL = "one-link-control-v1";
  const WEBRTC_BULK_LABEL = "one-link-bulk-v1";
  const WEBRTC_BULK_BUFFER_LOW_BYTES = 1 * 1024 * 1024;
  const WEBRTC_BULK_BUFFER_MAX_BYTES = 16 * 1024 * 1024;

  function assertWebRtcAvailable() {
    if (!window.RTCPeerConnection) {
      throw new Error("WebRTC unavailable in this browser");
    }
    if (!window.RTCSessionDescription) {
      throw new Error("RTCSessionDescription unavailable in this browser");
    }
    return true;
  }

  function _requirePlainObject(value, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`${label} must be an object`);
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new Error(`${label} must be a plain object`);
    }
    return value;
  }

  function _requireExactKeys(value, required, optional, label) {
    _requirePlainObject(value, label);
    const allowed = new Set(required.concat(optional || []));
    const actual = Object.keys(value);
    if (actual.some((key) => !allowed.has(key)) ||
        required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) {
      throw new Error(`${label} fields do not match the protocol`);
    }
    return value;
  }

  function _canonicalB64UrlBytes(value, expectedBytes, label) {
    if (typeof value !== "string" || !value ||
        value.length > Math.ceil((expectedBytes * 4) / 3) ||
        !/^[A-Za-z0-9_-]+$/.test(value)) {
      throw new Error(`${label} is not canonical base64url`);
    }
    let decoded;
    try {
      decoded = b64UrlToBytes(value);
    } catch (_) {
      throw new Error(`${label} is not canonical base64url`);
    }
    if (decoded.byteLength !== expectedBytes || bytesToB64Url(decoded) !== value) {
      throw new Error(`${label} is not canonical base64url for ${expectedBytes} bytes`);
    }
    return decoded;
  }

  function _canonicalSha256Fingerprint(value, label = "fingerprint") {
    if (typeof value !== "string" || !SHA256_FINGERPRINT_RE.test(value)) {
      throw new Error(`${label} must be canonical sha256:<lowercase-hex>`);
    }
    return value;
  }

  async function _validatePeerBinding(fingerprint, publicKeyB64u, label = "peer") {
    const canonicalFingerprint = _canonicalSha256Fingerprint(
      fingerprint, `${label} fingerprint`,
    );
    const publicKeyBytes = _canonicalB64UrlBytes(
      publicKeyB64u, ED25519_PUBLIC_KEY_BYTES, `${label} Ed25519 public key`,
    );
    if (!await _wasmEd25519ValidatePublic(publicKeyBytes)) {
      throw new Error(`${label} Ed25519 public key is malformed or weak`);
    }
    try {
      await crypto.subtle.importKey(
        "raw", publicKeyBytes, { name: "Ed25519" }, false, ["verify"],
      );
    } catch (error) {
      if (_isEd25519Unsupported(error)) {
        // The reviewed RustCrypto validator above is authoritative on engines
        // without native Ed25519 support.
      } else {
      throw new Error(`${label} Ed25519 public key is not importable`);
      }
    }
    const derivedFingerprint = await fingerprintOf(publicKeyBytes);
    if (derivedFingerprint !== canonicalFingerprint) {
      throw new Error(`${label} fingerprint does not match sha256(public key)`);
    }
    return {
      fingerprint: canonicalFingerprint,
      public_key_b64u: publicKeyB64u,
      public_key_bytes: publicKeyBytes,
    };
  }

  function _validateSignalBody(type, body) {
    _requirePlainObject(body, "signal body");
    if (type === "offer" || type === "answer") {
      _requireExactKeys(body, ["sdp", "type"], [], "session description");
      if (body.type !== type || typeof body.sdp !== "string" || !body.sdp ||
          body.sdp.length > WRTC_SDP_MAX_CHARS) {
        throw new Error(`invalid ${type} session description`);
      }
      return body;
    }
    if (type === "ice") {
      _requireExactKeys(
        body,
        ["candidate"],
        ["sdpMLineIndex", "sdpMid", "usernameFragment"],
        "ICE candidate",
      );
      if (typeof body.candidate !== "string" || !body.candidate ||
          body.candidate.length > WRTC_ICE_CANDIDATE_MAX_CHARS) {
        throw new Error("invalid ICE candidate");
      }
      if (body.sdpMid !== undefined && body.sdpMid !== null &&
          (typeof body.sdpMid !== "string" || body.sdpMid.length > 256)) {
        throw new Error("invalid ICE sdpMid");
      }
      if (body.usernameFragment !== undefined && body.usernameFragment !== null &&
          (typeof body.usernameFragment !== "string" ||
           body.usernameFragment.length > 256)) {
        throw new Error("invalid ICE usernameFragment");
      }
      if (body.sdpMLineIndex !== undefined && body.sdpMLineIndex !== null &&
          (!Number.isInteger(body.sdpMLineIndex) || body.sdpMLineIndex < 0 ||
           body.sdpMLineIndex > 65_535)) {
        throw new Error("invalid ICE sdpMLineIndex");
      }
      return body;
    }
    throw new Error(`unsupported signal type: ${type}`);
  }

  async function _signSignal(type, body) {
    if (!state.rec) throw new Error("identity not unlocked");
    if (type !== "offer" && type !== "answer" && type !== "ice") {
      throw new Error(`unsupported signal type: ${type}`);
    }
    _validateSignalBody(type, body);
    const signing = {
      v: WRTC_PROTOCOL_VERSION,
      type: String(type),
      sender_pubkey_b64: state.rec.public_key_b64u,
      timestamp_ms: Date.now(),
      body,
    };
    const enc = new TextEncoder();
    const sig = await _signEd25519(
      state.rec.private_key_jwk,
      enc.encode(_canonicalJson(signing)),
    );
    return Object.assign({}, signing, { signature: bytesToB64Url(sig) });
  }

  async function verifySignal(envelope, expectedType) {
    _requireExactKeys(envelope, WRTC_SIGNAL_KEYS, [], "WebRTC signal");
    if (!envelope || envelope.v !== WRTC_PROTOCOL_VERSION) {
      throw new Error("not a One Link WebRTC signal");
    }
    if (envelope.type !== "offer" && envelope.type !== "answer" &&
        envelope.type !== "ice") {
      throw new Error(`unsupported signal type: ${envelope.type}`);
    }
    if (expectedType && envelope.type !== expectedType) {
      throw new Error(`expected ${expectedType}, got ${envelope.type}`);
    }
    if (!Number.isSafeInteger(envelope.timestamp_ms) || envelope.timestamp_ms < 0 ||
        Math.abs(Date.now() - envelope.timestamp_ms) > WRTC_SIGNAL_TTL_MS) {
      throw new Error("signal expired");
    }
    _validateSignalBody(envelope.type, envelope.body);
    const wireBytes = new TextEncoder().encode(_canonicalJson(envelope));
    if (wireBytes.byteLength > WRTC_SIGNAL_MAX_BYTES) {
      throw new Error("WebRTC signal exceeds the protocol size limit");
    }
    const pub = _canonicalB64UrlBytes(
      envelope.sender_pubkey_b64,
      ED25519_PUBLIC_KEY_BYTES,
      "signal Ed25519 public key",
    );
    const sig = _canonicalB64UrlBytes(
      envelope.signature,
      ED25519_SIGNATURE_BYTES,
      "signal signature",
    );
    const signing = {
      v: envelope.v,
      type: envelope.type,
      sender_pubkey_b64: envelope.sender_pubkey_b64,
      timestamp_ms: envelope.timestamp_ms,
      body: envelope.body,
    };
    const enc = new TextEncoder();
    const ok = await _verifyEd25519(pub, sig, enc.encode(_canonicalJson(signing)));
    if (!ok) throw new Error("signal signature does not verify");
    return envelope;
  }

  function encodeSignal(envelope) {
    return bytesToB64Url(new TextEncoder().encode(JSON.stringify(envelope)));
  }

  function decodeSignal(textValue) {
    const s = String(textValue || "").trim();
    if (!s) throw new Error("empty signal");
    if (s.length > WRTC_SIGNAL_TEXT_MAX_CHARS) {
      throw new Error("signal text exceeds the protocol size limit");
    }
    try {
      return JSON.parse(s);
    } catch {
      const raw = b64UrlToBytes(s);
      return JSON.parse(new TextDecoder().decode(raw));
    }
  }

  async function _verifiedSignalBinding(envelope, expectedType) {
    const verified = await verifySignal(envelope, expectedType);
    const publicKeyBytes = _canonicalB64UrlBytes(
      verified.sender_pubkey_b64,
      ED25519_PUBLIC_KEY_BYTES,
      "signal Ed25519 public key",
    );
    return {
      envelope: verified,
      public_key_b64u: verified.sender_pubkey_b64,
      fingerprint: await fingerprintOf(publicKeyBytes),
    };
  }

  function _assertSignalSignerContinuity(session, binding) {
    if (!session || !session.pc) throw new Error("missing session");
    if (session.remote_signal_signer_pubkey_b64u &&
        session.remote_signal_signer_pubkey_b64u !== binding.public_key_b64u) {
      throw new Error("remote signaling signer changed within the WebRTC session");
    }
    if (session.remote_signal_signer_fingerprint &&
        session.remote_signal_signer_fingerprint !== binding.fingerprint) {
      throw new Error("remote signaling fingerprint changed within the WebRTC session");
    }
  }

  function _commitSignalSigner(session, binding) {
    _assertSignalSignerContinuity(session, binding);
    session.remote_signal_signer_pubkey_b64u = binding.public_key_b64u;
    session.remote_signal_signer_fingerprint = binding.fingerprint;
  }

