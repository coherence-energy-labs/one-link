  // ── v0.20.2 — daemon DataChannel router + roster + chat ───────────
  //
  // Once the auto-pair flow's controlDc opens, we register it as the
  // live transport to the daemon. From there:
  //
  //   - Outgoing requests use _daemonRequest("fetch_peers", {})
  //     which assigns a fresh rid (uuid), sends the envelope, and
  //     returns a Promise that resolves on the matching response or
  //     rejects on timeout (10s) / channel close.
  //
  //   - Incoming frames hit _routeDaemonDcMessage, which looks up
  //     the pending Promise by rid and resolves/rejects it.
  //
  //   - The roster + chat UI build on top: _refreshDaemonRoster
  //     fetches fetch_peers, renders rows. Tap a row → fetch_messages
  //     for that peer → render the chat view.
  //
  // Browser-to-browser chat (v0.19.2) and browser-to-daemon chat are
  // independent surfaces — different cards, different wires. v0.19.2's
  // pairing/chat lives on the v0.18.0 control DataChannel between two
  // browsers; v0.20.2's daemon-roster lives on the v0.20.0 daemon
  // control DataChannel. They never collide.

  state.daemon_dc = null;
  state.daemon_dc_fingerprint = null;
  state.daemon_pending = new Map();   // rid → {resolve, reject, timer}
  state.daemon_active_peer = null;     // currently-selected peer in the chat view
  state.daemon_reply_to = null;        // {id, body} selected in phone chat
  state.daemon_active_group = null;    // currently-selected group in the chat view
  state.daemon_identity_ready = null;
  state.daemon_identity_context = null;

  const DAEMON_REQUEST_TIMEOUT_MS = 10_000;
  const BROWSER_IDENTITY_POSSESSION_SCHEMA =
    "OL-BROWSER-IDENTITY-POSSESSION-1";
  const BROWSER_IDENTITY_CHALLENGE_TTL_MS = 15_000;
  const BROWSER_IDENTITY_MAX_CLOCK_SKEW_MS = 5_000;
  const BROWSER_IDENTITY_SIGNING_DOMAIN =
    "one-link/browser-identity-possession/v1\u0000";

  function _identityPossessionSigningBytes(challenge) {
    return new TextEncoder().encode(
      BROWSER_IDENTITY_SIGNING_DOMAIN + _canonicalJson(challenge),
    );
  }

  function _genRid() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return bytesToB64Url(_randomBytes(16));
  }

  function _registerDaemonDc(dc, daemonFingerprint) {
    const previousDc = state.daemon_dc;
    if (previousDc && previousDc !== dc) {
      // Request/response correlation is scoped to one authenticated channel.
      // A delayed reply from the replaced SCTP association must never settle
      // a request issued on the replacement association.
      for (const [, pending] of state.daemon_pending) {
        clearTimeout(pending.timer);
        pending.reject(new Error("daemon channel replaced"));
      }
      state.daemon_pending.clear();
      const previousIdentityReady = state.daemon_identity_ready;
      if (
        previousIdentityReady &&
        previousIdentityReady.dc === previousDc &&
        !previousIdentityReady.settled
      ) {
        previousIdentityReady.settled = true;
        previousIdentityReady.reject(new Error("daemon channel replaced"));
      }
    }
    state.daemon_dc = dc;
    state.daemon_dc_fingerprint = daemonFingerprint;
    state.daemon_identity_context = null;
    let resolveIdentity, rejectIdentity;
    const identityPromise = new Promise((resolve, reject) => {
      resolveIdentity = resolve;
      rejectIdentity = reject;
    });
    state.daemon_identity_ready = {
      dc,
      promise: identityPromise,
      resolve: resolveIdentity,
      reject: rejectIdentity,
      settled: false,
      verified: false,
    };
    dc.addEventListener("close", () => {
      // A close callback from an older DataChannel can run after a newer
      // channel has become current. It owns no current state and must not
      // clear the new channel or reject the new channel's requests.
      if (state.daemon_dc !== dc) return;
      const identityReady = state.daemon_identity_ready;
      const wasVerified = Boolean(
        identityReady && identityReady.dc === dc && identityReady.verified
      );
      if (identityReady && identityReady.dc === dc && !identityReady.settled) {
        identityReady.settled = true;
        identityReady.reject(new Error("identity-possession channel closed"));
      }
      state.daemon_dc = null;
      state.daemon_dc_fingerprint = null;
      state.daemon_identity_context = null;
      // Fail any in-flight requests.
      for (const [, pending] of state.daemon_pending) {
        clearTimeout(pending.timer);
        pending.reject(new Error("daemon channel closed"));
      }
      state.daemon_pending.clear();
      // 2026-05-23: auto-reconnect attempt. If the DC closed
      // because of an oversized message / ICE failure / daemon
      // restart, the user is now stuck with "no live channel"
      // forever unless they manually reload. We have a valid
      // cert; try the cert-authed relogin path immediately so
      // the user keeps going.
      if (wasVerified) _attemptDcAutoReconnect();
    });
    if (previousDc && previousDc !== dc) {
      try { previousDc.close(); } catch (_) {}
    }
    return identityPromise;
  }

  function _failDaemonIdentityPossession(dc, error) {
    const ready = state.daemon_identity_ready;
    if (ready && ready.dc === dc && !ready.settled) {
      ready.settled = true;
      ready.reject(error instanceof Error ? error : new Error(String(error)));
    }
    try { dc.close(); } catch (_) {}
  }

  async function _handleDaemonIdentityChallenge(msg, dc) {
    try {
      if (!dc || dc !== state.daemon_dc || dc.readyState !== "open") {
        throw new Error("identity challenge arrived on a stale channel");
      }
      _requireExactKeys(
        msg,
        [
          "challenge_id", "daemon_fingerprint", "expires_ms", "issued_ms",
          "nonce", "peer_fingerprint", "schema", "session_id", "t", "v",
        ],
        [],
        "identity-possession challenge",
      );
      if (
        msg.v !== "OL-PEER-1" ||
        msg.t !== "identity_possession_challenge" ||
        msg.schema !== BROWSER_IDENTITY_POSSESSION_SCHEMA
      ) {
        throw new Error("identity challenge protocol is invalid");
      }
      _canonicalB64UrlBytes(msg.challenge_id, 16, "identity challenge id");
      _canonicalB64UrlBytes(msg.nonce, 32, "identity challenge nonce");
      _canonicalB64UrlBytes(msg.session_id, 16, "identity session id");
      const peerFingerprint = _canonicalSha256Fingerprint(
        msg.peer_fingerprint, "identity peer fingerprint",
      );
      const daemonFingerprint = _canonicalSha256Fingerprint(
        msg.daemon_fingerprint, "identity daemon fingerprint",
      );
      if (!state.rec || peerFingerprint !== state.rec.fingerprint) {
        throw new Error("identity challenge targets another browser key");
      }
      if (daemonFingerprint !== state.daemon_dc_fingerprint) {
        throw new Error("identity challenge names another daemon");
      }
      if (
        !Number.isSafeInteger(msg.issued_ms) ||
        !Number.isSafeInteger(msg.expires_ms) ||
        msg.expires_ms - msg.issued_ms !== BROWSER_IDENTITY_CHALLENGE_TTL_MS ||
        Date.now() < msg.issued_ms - BROWSER_IDENTITY_MAX_CLOCK_SKEW_MS ||
        Date.now() >= msg.expires_ms
      ) {
        throw new Error("identity challenge is expired or malformed");
      }
      const prior = state.daemon_identity_context;
      if (prior && prior.dc === dc) {
        if (_canonicalJson(prior.challenge) !== _canonicalJson(msg)) {
          throw new Error("conflicting identity challenge on one channel");
        }
      }
      const signature = await _signEd25519(
        state.rec.private_key_jwk,
        _identityPossessionSigningBytes(msg),
      );
      if (dc !== state.daemon_dc || dc.readyState !== "open") {
        throw new Error("identity channel changed while signing");
      }
      state.daemon_identity_context = {dc, challenge: msg};
      dc.send(JSON.stringify({
        v: "OL-PEER-1",
        t: "identity_possession_response",
        schema: BROWSER_IDENTITY_POSSESSION_SCHEMA,
        challenge_id: msg.challenge_id,
        session_id: msg.session_id,
        peer_fingerprint: state.rec.fingerprint,
        signature: bytesToB64Url(signature),
      }));
    } catch (error) {
      _failDaemonIdentityPossession(dc, error);
    }
  }

  function _handleDaemonIdentityVerified(msg, dc) {
    try {
      if (!dc || dc !== state.daemon_dc || dc.readyState !== "open") {
        throw new Error("identity verification arrived on a stale channel");
      }
      _requireExactKeys(
        msg,
        [
          "challenge_id", "schema", "session_id", "t", "v", "verified_ms",
        ],
        [],
        "identity-possession verification",
      );
      if (
        msg.v !== "OL-PEER-1" ||
        msg.t !== "identity_possession_verified" ||
        msg.schema !== BROWSER_IDENTITY_POSSESSION_SCHEMA ||
        !Number.isSafeInteger(msg.verified_ms)
      ) {
        throw new Error("identity verification protocol is invalid");
      }
      const context = state.daemon_identity_context;
      const now = Date.now();
      if (
        !context || context.dc !== dc ||
        msg.challenge_id !== context.challenge.challenge_id ||
        msg.session_id !== context.challenge.session_id ||
        msg.verified_ms < (
          context.challenge.issued_ms - BROWSER_IDENTITY_MAX_CLOCK_SKEW_MS
        ) ||
        msg.verified_ms >= context.challenge.expires_ms ||
        msg.verified_ms > now + BROWSER_IDENTITY_MAX_CLOCK_SKEW_MS ||
        now >= (
          context.challenge.expires_ms + BROWSER_IDENTITY_MAX_CLOCK_SKEW_MS
        )
      ) {
        throw new Error("identity verification binding does not match");
      }
      const ready = state.daemon_identity_ready;
      if (!ready || ready.dc !== dc || ready.settled) return;
      ready.settled = true;
      ready.verified = true;
      ready.resolve({
        challenge_id: msg.challenge_id,
        session_id: msg.session_id,
        verified_ms: msg.verified_ms,
      });
    } catch (error) {
      _failDaemonIdentityPossession(dc, error);
    }
  }

