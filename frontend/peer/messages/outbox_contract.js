  function _messageDbRequest(request, label) {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(
        request.error || new Error(`${label} failed`),
      );
    });
  }

  function _messageDbTransactionDone(transaction, label) {
    return new Promise((resolve, reject) => {
      transaction.oncomplete = () => resolve();
      transaction.onabort = () => reject(
        transaction.error || new Error(`${label} aborted`),
      );
      transaction.onerror = () => {
        // IndexedDB follows a transaction error with abort. The abort handler
        // owns rejection so callers receive one deterministic failure.
      };
    });
  }

  function _chatOutboxKey(ownerFp, peerFp, id) {
    return `${ownerFp}::${peerFp}::${id}`;
  }

  function _activeChatBinding(pairing, requireOpen = true) {
    const p = pairing || state.pairing;
    if (!state.rec || !p || !p.persisted || !p.finished || !p.remote_hello
        || p.local_confirm !== true || p.remote_confirm !== true) {
      throw new Error("no mutually-confirmed paired peer on the active connection");
    }
    if (!p.session || !p.session.control
        || (requireOpen && p.session.control.readyState !== "open")) {
      throw new Error("paired control channel is not open");
    }
    const ownerFp = _canonicalSha256Fingerprint(
      state.rec.fingerprint, "local chat identity fingerprint",
    );
    const peerFp = _canonicalSha256Fingerprint(
      p.remote_hello.fingerprint, "remote chat identity fingerprint",
    );
    if (p.local_identity_fingerprint !== ownerFp
        || p.local_identity_pubkey_b64u !== state.rec.public_key_b64u) {
      throw new Error("chat session belongs to a different local identity");
    }
    if (p.session.remote_signal_signer_fingerprint !== peerFp
        || p.session.remote_signal_signer_pubkey_b64u !== p.remote_hello.pubkey) {
      throw new Error("chat session is not bound to the paired signaling identity");
    }
    if (!p.chat_session_id) p.chat_session_id = _newMessageId();
    if (!_validStoredMessageId(p.chat_session_id)) {
      throw new Error("chat session id is invalid");
    }
    return {
      owner_fp: ownerFp,
      owner_pubkey_b64u: state.rec.public_key_b64u,
      peer_fp: peerFp,
      peer_pubkey_b64u: p.remote_hello.pubkey,
      session_id: p.chat_session_id,
      pairing: p,
    };
  }

  function _chatWireJson(wire) {
    return JSON.stringify({
      v: wire.v,
      t: wire.t,
      id: wire.id,
      body: wire.body,
      ts: wire.ts,
    });
  }

  async function _normalizeChatOutboxRow(row) {
    const expected = [
      "attempt_count", "body", "id", "key", "last_attempt_ms",
      "last_session_id", "owner_fp", "owner_pubkey_b64u", "peer_fp",
      "peer_pubkey_b64u", "queued_ms", "ts", "v", "wire_json",
    ];
    if (!row || typeof row !== "object" || Array.isArray(row)
        || Object.keys(row).length !== expected.length
        || expected.some((key) => !Object.prototype.hasOwnProperty.call(row, key))) {
      throw new Error("chat outbox row has an unsupported schema");
    }
    if (row.v !== 1) throw new Error("chat outbox row version is unsupported");
    if (!_validStoredMessageId(row.id)) throw new Error("invalid chat outbox id");
    const owner = await _validatePeerBinding(
      row.owner_fp, row.owner_pubkey_b64u, "chat outbox owner",
    );
    const peer = await _validatePeerBinding(
      row.peer_fp, row.peer_pubkey_b64u, "chat outbox peer",
    );
    const message = _normalizeStoredMessage({
      id: row.id,
      peer_fp: peer.fingerprint,
      direction: "out",
      body: row.body,
      ts: row.ts,
      received_ms: row.queued_ms,
    });
    if (!Number.isSafeInteger(row.queued_ms) || row.queued_ms <= 0
        || row.queued_ms > Date.now() + MSG_FUTURE_SKEW_MS) {
      throw new Error("invalid chat outbox queue timestamp");
    }
    if (!Number.isSafeInteger(row.attempt_count) || row.attempt_count < 0
        || row.attempt_count > Number.MAX_SAFE_INTEGER) {
      throw new Error("invalid chat outbox attempt count");
    }
    if (row.last_attempt_ms !== null
        && (!Number.isSafeInteger(row.last_attempt_ms)
          || row.last_attempt_ms <= 0
          || row.last_attempt_ms > Date.now() + MSG_FUTURE_SKEW_MS)) {
      throw new Error("invalid chat outbox attempt timestamp");
    }
    if (row.last_session_id !== null
        && !_validStoredMessageId(row.last_session_id)) {
      throw new Error("invalid chat outbox session binding");
    }
    let wire;
    try {
      wire = JSON.parse(row.wire_json);
    } catch (_) {
      throw new Error("chat outbox wire payload is not JSON");
    }
    if (!wire || Array.isArray(wire)
        || Object.keys(wire).length !== 5
        || ["v", "t", "id", "body", "ts"].some(
          (key) => !Object.prototype.hasOwnProperty.call(wire, key),
        )
        || wire.v !== MSG_PROTOCOL_VERSION || wire.t !== "text"
        || wire.id !== row.id || wire.body !== row.body || wire.ts !== row.ts
        || row.wire_json !== _chatWireJson(wire)) {
      throw new Error("chat outbox wire payload does not match its authority row");
    }
    const key = _chatOutboxKey(owner.fingerprint, peer.fingerprint, row.id);
    if (row.key !== key) throw new Error("chat outbox key does not match its bindings");
    return Object.assign({}, row, {
      key,
      owner_fp: owner.fingerprint,
      owner_pubkey_b64u: owner.public_key_b64u,
      peer_fp: peer.fingerprint,
      peer_pubkey_b64u: peer.public_key_b64u,
      message,
      wire,
    });
  }

  function _sameChatOutboxPayload(a, b) {
    return Boolean(a && b)
      && a.v === b.v && a.key === b.key && a.id === b.id
      && a.owner_fp === b.owner_fp
      && a.owner_pubkey_b64u === b.owner_pubkey_b64u
      && a.peer_fp === b.peer_fp
      && a.peer_pubkey_b64u === b.peer_pubkey_b64u
      && a.body === b.body && a.ts === b.ts
      && a.queued_ms === b.queued_ms && a.wire_json === b.wire_json;
  }

  function _sameChatOutboxSnapshot(a, b) {
    return _sameChatOutboxPayload(a, b)
      && a.attempt_count === b.attempt_count
      && a.last_attempt_ms === b.last_attempt_ms
      && a.last_session_id === b.last_session_id;
  }

  function _makeChatOutboxRow(rec, wire, binding) {
    return {
      v: 1,
      key: _chatOutboxKey(binding.owner_fp, binding.peer_fp, rec.id),
      id: rec.id,
      owner_fp: binding.owner_fp,
      owner_pubkey_b64u: binding.owner_pubkey_b64u,
      peer_fp: binding.peer_fp,
      peer_pubkey_b64u: binding.peer_pubkey_b64u,
      body: rec.body,
      ts: rec.ts,
      wire_json: _chatWireJson(wire),
      queued_ms: rec.received_ms,
      attempt_count: 0,
      last_attempt_ms: null,
      last_session_id: null,
    };
  }

  function _storedChatOutboxRow(row) {
    return {
      v: row.v,
      key: row.key,
      id: row.id,
      owner_fp: row.owner_fp,
      owner_pubkey_b64u: row.owner_pubkey_b64u,
      peer_fp: row.peer_fp,
      peer_pubkey_b64u: row.peer_pubkey_b64u,
      body: row.body,
      ts: row.ts,
      wire_json: row.wire_json,
      queued_ms: row.queued_ms,
      attempt_count: row.attempt_count,
      last_attempt_ms: row.last_attempt_ms,
      last_session_id: row.last_session_id,
    };
  }

