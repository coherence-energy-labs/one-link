  // ── chat send + receive ────────────────────────────────────────────

  // Inbound rate window per peer fingerprint (MSG_RATE_MAX_PER_PEER new
  // messages per MSG_RATE_WINDOW_MS). Owned by the receive path below.
  const _messageRateByPeer = new Map();

  async function sendChatMessage(body) {
    const p = state.pairing;
    const binding = _activeChatBinding(p, true);
    if (!body || typeof body !== "string") {
      throw new Error("message body required");
    }
    const trimmed = body.trim();
    if (!trimmed) throw new Error("empty message");
    const enc = new TextEncoder();
    if (enc.encode(trimmed).byteLength > MSG_BODY_MAX_BYTES) {
      throw new Error(`message exceeds ${MSG_BODY_MAX_BYTES} bytes`);
    }
    const id = _newMessageId();
    const ts = Date.now();
    const peer_fp = p.remote_hello.fingerprint;
    const wire = {
      v: MSG_PROTOCOL_VERSION,
      t: "text",
      id,
      body: trimmed,
      ts,
    };
    const rec = {
      id,
      peer_fp,
      direction: "out",
      body: trimmed,
      ts,
      received_ms: ts,
    };
    // History and the identity-bound outbox authority commit atomically before
    // any remotely-visible frame.
    await persistOutboundMessage(rec, wire, binding);
    try {
      const replay = await drainChatOutbox(p);
      rec.queued = !replay.sent_ids.includes(id);
      if (replay.stopped) rec.queue_status = replay.stopped;
    } catch (error) {
      // Admission already committed. Keep the same id/payload for a verified
      // reconnect instead of inviting a second user-generated send.
      rec.queued = true;
      rec.queue_status = error && error.message ? error.message : String(error);
    }
    return rec;
  }

  async function _onChatTextReceived(envelope) {
    const p = state.pairing;
    if (!p || !p.remote_hello) return;
    if (envelope.v !== MSG_PROTOCOL_VERSION || envelope.t !== "text") return;
    if (Object.keys(envelope).some((key) =>
      !["v", "t", "id", "body", "ts"].includes(key))) return;
    const id = envelope.id;
    const body = envelope.body;
    const ts = envelope.ts;
    if (!_validStoredMessageId(id) || typeof body !== "string" || !body.length ||
        !Number.isSafeInteger(ts) || ts <= 0
        || ts > Date.now() + MSG_FUTURE_SKEW_MS) return;
    const enc = new TextEncoder();
    if (enc.encode(body).byteLength > MSG_BODY_MAX_BYTES) return;
    const peer_fp = binding.peer_fp;
    const now = Date.now();
    const existing = await getStoredMessage(peer_fp, id);
    if (!existing) {
      const rate = _messageRateByPeer.get(peer_fp) || [];
      while (rate.length && rate[0] < now - MSG_RATE_WINDOW_MS) rate.shift();
      if (rate.length >= MSG_RATE_MAX_PER_PEER) return;
      rate.push(now);
      _messageRateByPeer.set(peer_fp, rate);
    }
    const rec = {
      id,
      peer_fp,
      direction: "in",
      body,
      ts,
      received_ms: now,
    };
    const saved = await saveMessage(rec);
    // Send ack back so the sender can mark it delivered.
    sendControl(p.session, {
      v: MSG_PROTOCOL_VERSION,
      t: "ack",
      id,
      ts: Date.now(),
      durable: true,
    });
    if (saved.inserted) _appendChatBubble(saved.record);
  }

  async function _onChatAckReceived(envelope) {
    const p = state.pairing;
    if (!p || !p.remote_hello) return;
    if (envelope.v !== MSG_PROTOCOL_VERSION || envelope.t !== "ack") return;
    if (Object.keys(envelope).some((key) =>
      !["v", "t", "id", "ts", "durable"].includes(key))) return;
    const id = envelope.id;
    const ackMs = envelope.ts;
    if (!_validStoredMessageId(id) || !Number.isSafeInteger(ackMs) || ackMs <= 0
        || ackMs > Date.now() + MSG_FUTURE_SKEW_MS
        || envelope.durable !== true) return;
    const binding = _activeChatBinding(p, true);
    await acknowledgeOutboundMessage(
      binding.owner_fp, binding.peer_fp, id, ackMs,
    );
    _markBubbleAcked(id);
  }

