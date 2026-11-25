  function _newPairing(session) {
    return {
      session,
      version: PAIR_PROTOCOL_VERSION,
      // Freeze the local authority at channel-open time. A later in-page
      // identity reset/unlock must not inherit this already-negotiated session.
      local_identity_fingerprint: state.rec ? state.rec.fingerprint : null,
      local_identity_pubkey_b64u: state.rec ? state.rec.public_key_b64u : null,
      local_nonce: _randomBytes(PAIR_NONCE_BYTES),
      remote_hello: null,
      sas: null,
      local_confirm: null,   // null | true | false
      remote_confirm: null,  // null | true | false
      sent_hello: false,
      sent_confirm: false,
      finalizing: false,
      persisted: false,
      finished: false,
      timeout: null,
    };
  }

  function _abortPairing(reason) {
    const p = state.pairing;
    if (!p || p.finished) return;
    p.finished = true;
    if (p.timeout) clearTimeout(p.timeout);
    text($("#pair-status"),
      reason ? `Pairing aborted: ${reason}` : "Pairing aborted.");
    hide($("#pair-sas-wrap"));
  }

  async function _sendPairHello() {
    const p = state.pairing;
    if (!p || p.sent_hello) return;
    if (!state.rec) throw new Error("identity not unlocked");
    if (p.local_identity_fingerprint !== state.rec.fingerprint
        || p.local_identity_pubkey_b64u !== state.rec.public_key_b64u) {
      throw new Error("local identity changed after the pair session opened");
    }
    const hello = {
      v: PAIR_PROTOCOL_VERSION,
      t: "hello",
      pubkey: state.rec.public_key_b64u,
      fingerprint: state.rec.fingerprint,
      nonce: bytesToB64Url(p.local_nonce),
      ts: Date.now(),
    };
    sendControl(p.session, hello);
    p.sent_hello = true;
  }

  async function _onPairHello(envelope) {
    const p = state.pairing;
    if (!p || p.finished || p.finalizing) return;
    let hello;
    try {
      hello = await _validatePairHello(envelope);
    } catch (error) {
      if (state.pairing !== p) return;
      _abortPairing(error && error.message ? error.message : String(error));
      return;
    }
    if (state.pairing !== p || p.finished || p.finalizing) return;
    const pinnedKey = p.session && p.session.remote_signal_signer_pubkey_b64u;
    const pinnedFingerprint = p.session && p.session.remote_signal_signer_fingerprint;
    if (!pinnedKey || !pinnedFingerprint) {
      _abortPairing("pair hello arrived without a verified signaling signer");
      return;
    }
    if (hello.pubkey !== pinnedKey || hello.fingerprint !== pinnedFingerprint) {
      _abortPairing("pair hello identity does not match the verified signaling signer");
      return;
    }
    if (state.rec && hello.fingerprint === state.rec.fingerprint) {
      _abortPairing("refusing to pair this identity with itself");
      return;
    }
    if (p.remote_hello) {
      // Exact retransmission is idempotent. A changed duplicate is a session
      // identity/nonce swap and must terminate the pairing.
      if (_canonicalJson(p.remote_hello) !== _canonicalJson(hello)) {
        _abortPairing("conflicting duplicate pair hello");
      }
      return;
    }
    p.remote_hello = hello;
    text($("#pair-peer-fp"), hello.fingerprint);
    show($("#pair-peer-wrap"));

    let sas;
    try {
      sas = await _computeSas(
        state.rec.public_key_b64u,
        bytesToB64Url(p.local_nonce),
        hello.pubkey,
        hello.nonce,
      );
    } catch (error) {
      if (state.pairing !== p) return;
      _abortPairing(
        `couldn't derive the pair verification code: ${
          error && error.message ? error.message : error
        }`,
      );
      return;
    }
    if (state.pairing !== p || p.finished || p.finalizing) return;
    p.sas = sas;
    text($("#pair-status"),
      "Compare all five words with the other device. Confirm only if every word and its order match.");
    text($("#pair-sas-words"), sas.phrase);
    text($("#pair-sas-digits"), sas.display);
    _renderSasArt($("#pair-sas-art"), sas.art);
    show($("#pair-sas-wrap"));
  }

  async function _sendPairConfirm(matched) {
    const p = state.pairing;
    if (!p || p.sent_confirm || !state.rec) return;
    p.local_confirm = matched;
    const msg = {
      v: PAIR_PROTOCOL_VERSION,
      t: "confirm",
      fingerprint: state.rec.fingerprint,
      matched: !!matched,
      ts: Date.now(),
    };
    sendControl(p.session, msg);
    p.sent_confirm = true;
    if (matched) {
      text($("#pair-status"),
        "You confirmed the match. Waiting for the other device to confirm…");
    } else {
      _abortPairing("you marked the codes as not matching");
    }
    await _maybeFinalizePairing();
  }

  async function _onPairConfirm(envelope) {
    const p = state.pairing;
    if (!p || p.finished || p.finalizing) return;
    try {
      _validatePairConfirm(envelope);
    } catch (error) {
      _abortPairing(error && error.message ? error.message : String(error));
      return;
    }
    if (!p.remote_hello || envelope.fingerprint !== p.remote_hello.fingerprint) {
      _abortPairing("pair confirmation identity does not match the pair hello");
      return;
    }
    if (p.remote_confirm !== null && p.remote_confirm !== envelope.matched) {
      _abortPairing("conflicting duplicate pair confirmation");
      return;
    }
    p.remote_confirm = envelope.matched;
    if (!envelope.matched) {
      _abortPairing("the other device marked the codes as not matching");
      return;
    }
    text($("#pair-status"),
      "Other device confirmed the match. Waiting for your confirmation…");
    await _maybeFinalizePairing();
  }

  async function _maybeFinalizePairing() {
    const p = state.pairing;
    if (!p || p.finished || p.finalizing) return;
    if (p.local_confirm !== true || p.remote_confirm !== true) return;
    if (!p.remote_hello) return;
    p.finalizing = true;
    const rec = {
      v: 1,
      fingerprint: p.remote_hello.fingerprint,
      public_key_b64u: p.remote_hello.pubkey,
      alias: p.remote_hello.alias || "",
      paired_ms: Date.now(),
      last_seen_ms: Date.now(),
      sas_digits: p.sas ? p.sas.digits : null,
    };
    try {
      await savePeer(rec);
    } catch (e) {
      p.finalizing = false;
      if (state.pairing !== p) {
        p.finished = true;
        return;
      }
      _abortPairing(
        `paired but couldn't save peer record: ${e && e.message ? e.message : e}`
      );
      return;
    }
    p.persisted = true;
    p.finished = true;
    p.finalizing = false;
    if (p.timeout) clearTimeout(p.timeout);
    if (state.pairing !== p) return;
    text($("#pair-status"),
      `Paired with ${rec.fingerprint}. Peer added to your roster.`);
    hide($("#pair-sas-wrap"));
    await _refreshPeersCard();
  }

  function _routeControlMessage(session, kind, data) {
    if (kind !== "control") return;
    const pairing = state.pairing;
    // A stale or concurrent DataChannel must never mutate the globally active
    // pairing. Session identity is checked before parsing or dispatch.
    if (!pairing || pairing.session !== session || pairing.finished ||
        pairing.finalizing) return;
    if (typeof data !== "string" || data.length > PAIR_MESSAGE_MAX_CHARS) {
      _abortPairing("malformed or oversized pair control frame");
      return;
    }
    let msg;
    try {
      msg = typeof data === "string" ? JSON.parse(data) : null;
    } catch {
      return;
    }
    if (!msg || msg.v !== PAIR_PROTOCOL_VERSION) return;
    if (msg.t === "hello") {
      void _onPairHello(msg);
    } else if (msg.t === "confirm") {
      void _onPairConfirm(msg);
    }
  }

  async function _onControlChannelOpen(session) {
    if (state.pairing && state.pairing.session === session) return;
    const previous = state.pairing;
    if (previous) {
      if (previous.timeout) clearTimeout(previous.timeout);
      previous.finished = true;
    }
    const pairing = _newPairing(session);
    state.pairing = pairing;
    pairing.timeout = setTimeout(() => {
      if (state.pairing === pairing && !pairing.finished &&
          !pairing.remote_hello) {
        _abortPairing("the other device didn't send a pair hello");
      }
    }, PAIR_HELLO_TIMEOUT_MS);
    show($("#pair-card"));
    text($("#pair-status"),
      "Channel open. Waiting for the other device's identity claim…");
    try {
      await _sendPairHello();
    } catch (e) {
      _abortPairing(
        `couldn't send pair hello: ${e && e.message ? e.message : e}`
      );
    }
  }

  $("#btn-pair-match")?.addEventListener("click", () => _sendPairConfirm(true));
  $("#btn-pair-mismatch")?.addEventListener("click", () => _sendPairConfirm(false));

