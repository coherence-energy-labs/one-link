  async function _reserveChatOutboxAttempt(db, snapshotRow, sessionId) {
    const tx = db.transaction(MSG_OUTBOX_STORE_NAME, "readwrite");
    const done = _messageDbTransactionDone(tx, "chat outbox attempt reserve");
    const store = tx.objectStore(MSG_OUTBOX_STORE_NAME);
    const current = await _messageDbRequest(
      store.get(snapshotRow.key), "chat outbox attempt lookup",
    );
    if (!current) {
      await done;
      return null;
    }
    if (!_sameChatOutboxPayload(current, snapshotRow)) {
      try { tx.abort(); } catch (_) {}
      try { await done; } catch (_) {}
      throw new Error("chat outbox row changed before send reservation");
    }
    if (current.last_session_id === sessionId) {
      await done;
      return null;
    }
    const reserved = Object.assign({}, current, {
      attempt_count: current.attempt_count + 1,
      last_attempt_ms: Date.now(),
      last_session_id: sessionId,
    });
    store.put(reserved);
    await done;
    return reserved;
  }

  async function _drainChatOutboxOnce(pairing = state.pairing) {
    const binding = _activeChatBinding(pairing, true);
    const db = await _openMessagesDb();
    const sentIds = [];
    let lastBatchWasFull = false;
    try {
      for (let batch = 0; batch < MSG_OUTBOX_MAX_BATCHES_PER_DRAIN; batch += 1) {
        const tx = db.transaction(MSG_OUTBOX_STORE_NAME, "readonly");
        const done = _messageDbTransactionDone(tx, "chat outbox snapshot");
        const rows = await _messageDbRequest(
          tx.objectStore(MSG_OUTBOX_STORE_NAME).getAll(
            null, MSG_OUTBOX_SCAN_MAX,
          ),
          "chat outbox snapshot",
        );
        await done;
        lastBatchWasFull = (rows || []).length >= MSG_OUTBOX_SCAN_MAX;
        const invalidRows = [];
        const validRows = [];
        for (const raw of rows || []) {
          let row;
          try {
            row = await _normalizeChatOutboxRow(raw);
          } catch (error) {
            invalidRows.push({
              row: raw,
              reason: error && error.message ? error.message : String(error),
            });
            continue;
          }
          if (row.owner_fp === binding.owner_fp
              && row.peer_fp === binding.peer_fp
              && (row.owner_pubkey_b64u !== binding.owner_pubkey_b64u
                || row.peer_pubkey_b64u !== binding.peer_pubkey_b64u)) {
            invalidRows.push({
              row: raw,
              reason: "chat outbox authority no longer matches its identity binding",
            });
            continue;
          }
          validRows.push({ raw, row });
        }
        const removedInvalid = await quarantineChatOutboxRows(db, invalidRows);
        for (const candidate of validRows) {
          const { raw, row } = candidate;
          if (row.owner_fp !== binding.owner_fp
              || row.peer_fp !== binding.peer_fp) {
            continue;
          }
          if (row.last_session_id === binding.session_id) continue;
          const live = _activeChatBinding(binding.pairing, true);
          if (live.session_id !== binding.session_id
              || live.owner_fp !== binding.owner_fp
              || live.peer_fp !== binding.peer_fp) {
            return { sent_ids: sentIds, stopped: "active pairing changed" };
          }
          // A manually-corrupted database could retain an outbox row without
          // its history row. Rebuild/check the exact local record before the
          // remotely-visible frame; conflicting IDs fail closed.
          await saveMessage(row.message);
          const reserved = await _reserveChatOutboxAttempt(
            db, raw, binding.session_id,
          );
          if (!reserved) continue;
          if (binding.pairing.session.control.readyState !== "open") {
            return { sent_ids: sentIds, stopped: "control channel closed" };
          }
          try {
            // Send the exact bytes admitted to the durable row. The session id
            // was committed first, so overlapping drain triggers cannot submit
            // the same message twice on one DataChannel session.
            binding.pairing.session.control.send(reserved.wire_json);
            sentIds.push(reserved.id);
          } catch (error) {
            return {
              sent_ids: sentIds,
              stopped: error && error.message ? error.message : String(error),
            };
          }
        }
        if (!lastBatchWasFull || removedInvalid === 0) break;
      }
      return {
        sent_ids: sentIds,
        stopped: lastBatchWasFull ? "bounded drain budget exhausted" : null,
      };
    } finally {
      db.close();
    }
  }

  let _chatOutboxDrainTail = Promise.resolve();
  function drainChatOutbox(pairing = state.pairing) {
    const operation = async () => {
      if (!navigator.locks || typeof navigator.locks.request !== "function") {
        throw new Error("Web Locks are required for collision-safe chat replay");
      }
      return navigator.locks.request(
        MSG_OUTBOX_LOCK_NAME, { mode: "exclusive" },
        () => _drainChatOutboxOnce(pairing),
      );
    };
    const run = _chatOutboxDrainTail.then(operation, operation);
    _chatOutboxDrainTail = run.catch(() => undefined);
    return run;
  }

  async function acknowledgeOutboundMessage(ownerFp, peerFp, id, ackMs) {
    if (!_validStoredMessageId(id) || !Number.isSafeInteger(ackMs) || ackMs <= 0
        || ackMs > Date.now() + MSG_FUTURE_SKEW_MS) {
      throw new Error("invalid message acknowledgement");
    }
    const owner = _canonicalSha256Fingerprint(
      ownerFp, "chat acknowledgement owner",
    );
    const peer = _canonicalSha256Fingerprint(
      peerFp, "chat acknowledgement peer",
    );
    const outboxKey = _chatOutboxKey(owner, peer, id);
    const db = await _openMessagesDb();
    try {
      const tx = db.transaction(
        [MSG_STORE_NAME, MSG_OUTBOX_STORE_NAME], "readwrite",
      );
      const done = _messageDbTransactionDone(tx, "chat acknowledgement commit");
      const messages = tx.objectStore(MSG_STORE_NAME);
      const queue = tx.objectStore(MSG_OUTBOX_STORE_NAME);
      try {
        const matches = await _messageDbRequest(
          messages.index("by_peer_id").getAll(
            IDBKeyRange.only([peer, id]), 2,
          ),
          "chat acknowledgement history lookup",
        );
        if (matches.length !== 1 || matches[0].direction !== "out") {
          throw new Error("ack does not bind to one outbound message");
        }
        const message = matches[0];
        const queued = await _messageDbRequest(
          queue.get(outboxKey), "chat acknowledgement outbox lookup",
        );
        if (queued && (queued.owner_fp !== owner || queued.peer_fp !== peer
            || queued.id !== id || queued.body !== message.body
            || queued.ts !== message.ts)) {
          throw new Error("acknowledgement does not match the queued payload");
        }
        if (!message.ack_ms) {
          message.ack_ms = ackMs;
          messages.put(message);
        }
        if (queued) queue.delete(outboxKey);
        await done;
        return message;
      } catch (error) {
        try { tx.abort(); } catch (_) {}
        try { await done; } catch (_) {}
        throw error;
      }
    } finally {
      db.close();
    }
  }

