  async function persistOutboundMessage(rec, wire, binding) {
    const message = _normalizeStoredMessage(rec);
    const outbox = _storedChatOutboxRow(
      await _normalizeChatOutboxRow(
        _makeChatOutboxRow(message, wire, binding),
      ),
    );
    const db = await _openMessagesDb();
    const tx = db.transaction(
      [MSG_STORE_NAME, MSG_OUTBOX_STORE_NAME], "readwrite",
    );
    const done = _messageDbTransactionDone(tx, "chat outbox admission");
    const messages = tx.objectStore(MSG_STORE_NAME);
    const queue = tx.objectStore(MSG_OUTBOX_STORE_NAME);
    try {
      const matches = await _messageDbRequest(
        messages.index("by_peer_id").getAll(
          IDBKeyRange.only([message.peer_fp, message.id]), 2,
        ),
        "chat history id lookup",
      );
      if (matches.length > 1 || (matches.length === 1
          && !_sameStoredMessage(matches[0], message))) {
        throw new Error("message id was reused for different content");
      }
      const existingOutbox = await _messageDbRequest(
        queue.get(outbox.key), "chat outbox id lookup",
      );
      if (existingOutbox && !_sameChatOutboxPayload(existingOutbox, outbox)) {
        throw new Error("chat outbox id was reused for different content");
      }
      if (matches.length === 0) {
        const historyCount = await _messageDbRequest(
          messages.index("by_peer").count(message.peer_fp),
          "chat history quota lookup",
        );
        if (historyCount >= MSG_MAX_ROWS_PER_PEER) {
          throw new Error("browser chat history quota reached");
        }
        messages.add(message);
      }
      if (!existingOutbox) {
        const perPeerCount = await _messageDbRequest(
          queue.index("by_owner_peer").count(
            IDBKeyRange.only([outbox.owner_fp, outbox.peer_fp]),
          ),
          "chat outbox peer quota lookup",
        );
        const totalCount = await _messageDbRequest(
          queue.count(), "chat outbox total quota lookup",
        );
        if (perPeerCount >= MSG_OUTBOX_MAX_ROWS_PER_PEER
            || totalCount >= MSG_OUTBOX_MAX_TOTAL_ROWS) {
          throw new Error("direct chat outbox quota reached");
        }
        queue.add(outbox);
      }
      await done;
    } catch (error) {
      try { tx.abort(); } catch (_) {}
      try { await done; } catch (_) {}
      throw error;
    } finally {
      db.close();
    }
    return { message, outbox };
  }

  function _sameRawChatOutboxRow(a, b) {
    if (!a || !b || a.key !== b.key) return false;
    try {
      return JSON.stringify(a) === JSON.stringify(b);
    } catch (_) {
      // IndexedDB can clone cyclic objects. Such a row is invalid by schema;
      // bind cleanup to its immutable primary key and core ownership fields.
      return a.id === b.id && a.owner_fp === b.owner_fp
        && a.peer_fp === b.peer_fp;
    }
  }

  function _chatOutboxQuarantineSummary(row, reason) {
    const clipped = (value, max) => typeof value === "string"
      ? value.slice(0, max) : `[${typeof value}]`;
    return {
      quarantined_ms: Date.now(),
      reason: clipped(reason || "invalid direct-chat outbox row", 200),
      source_key: clipped(row && row.key, 768),
      source_id: clipped(row && row.id, 128),
      owner_fp: clipped(row && row.owner_fp, 96),
      peer_fp: clipped(row && row.peer_fp, 96),
      body_code_units: typeof (row && row.body) === "string"
        ? Math.min(row.body.length, Number.MAX_SAFE_INTEGER) : null,
    };
  }

  async function quarantineChatOutboxRows(db, invalidRows) {
    if (!invalidRows.length) return 0;
    const tx = db.transaction(MSG_OUTBOX_STORE_NAME, "readwrite");
    const done = _messageDbTransactionDone(tx, "invalid chat outbox cleanup");
    const store = tx.objectStore(MSG_OUTBOX_STORE_NAME);
    const currentRows = await Promise.all(invalidRows.map(({ row }) =>
      _messageDbRequest(
        store.get(row && row.key), "invalid chat outbox exact lookup",
      )
    ));
    const removed = [];
    for (let index = 0; index < invalidRows.length; index += 1) {
      const candidate = invalidRows[index];
      if (_sameRawChatOutboxRow(currentRows[index], candidate.row)) {
        store.delete(candidate.row.key);
        removed.push(candidate);
      }
    }
    await done;
    if (!removed.length) return 0;
    try {
      const qtx = db.transaction(MSG_QUARANTINE_STORE_NAME, "readwrite");
      const qdone = _messageDbTransactionDone(qtx, "chat outbox quarantine batch");
      const quarantine = qtx.objectStore(MSG_QUARANTINE_STORE_NAME);
      const existing = await _messageDbRequest(
        quarantine.getAll(null, MSG_OUTBOX_QUARANTINE_MAX_ROWS),
        "chat outbox quarantine history",
      );
      const summaries = (existing || []).concat(removed.map(({ row, reason }) =>
        _chatOutboxQuarantineSummary(row, reason)
      )).slice(-MSG_OUTBOX_QUARANTINE_MAX_ROWS);
      quarantine.clear();
      for (const summary of summaries) {
        const copy = Object.assign({}, summary);
        delete copy.quarantine_id;
        quarantine.add(copy);
      }
      await qdone;
    } catch (_) {
      // Diagnostics are bounded and best-effort. Removal from the executable
      // queue was already committed, so poison cannot retain head-of-line.
    }
    return removed.length;
  }

  async function listChatOutbox(ownerFp = null, peerFp = null) {
    const db = await _openMessagesDb();
    try {
      const tx = db.transaction(MSG_OUTBOX_STORE_NAME, "readonly");
      const done = _messageDbTransactionDone(tx, "chat outbox list");
      const store = tx.objectStore(MSG_OUTBOX_STORE_NAME);
      let request;
      if (ownerFp !== null && peerFp !== null) {
        request = store.index("by_owner_peer").getAll(
          IDBKeyRange.only([ownerFp, peerFp]), MSG_OUTBOX_SCAN_MAX,
        );
      } else {
        request = store.getAll(null, MSG_OUTBOX_SCAN_MAX);
      }
      const rows = await _messageDbRequest(request, "chat outbox list");
      await done;
      return rows || [];
    } finally {
      db.close();
    }
  }

  async function listChatOutboxQuarantine() {
    const db = await _openMessagesDb();
    try {
      const tx = db.transaction(MSG_QUARANTINE_STORE_NAME, "readonly");
      const done = _messageDbTransactionDone(tx, "chat outbox quarantine list");
      const rows = await _messageDbRequest(
        tx.objectStore(MSG_QUARANTINE_STORE_NAME).getAll(
          null, MSG_OUTBOX_QUARANTINE_MAX_ROWS,
        ),
        "chat outbox quarantine list",
      );
      await done;
      return rows || [];
    } finally {
      db.close();
    }
  }

  async function clearChatOutboxForPeer(peerFp, ownerFp = null) {
    const canonicalPeer = _canonicalSha256Fingerprint(
      peerFp, "chat outbox cleanup peer",
    );
    const canonicalOwner = ownerFp === null ? null : _canonicalSha256Fingerprint(
      ownerFp, "chat outbox cleanup owner",
    );
    const db = await _openMessagesDb();
    try {
      const tx = db.transaction(MSG_OUTBOX_STORE_NAME, "readwrite");
      const done = _messageDbTransactionDone(tx, "chat outbox peer cleanup");
      const store = tx.objectStore(MSG_OUTBOX_STORE_NAME);
      const rows = await _messageDbRequest(
        store.getAll(null, MSG_OUTBOX_MAX_TOTAL_ROWS),
        "chat outbox peer cleanup scan",
      );
      let deleted = 0;
      for (const row of rows || []) {
        if (row && row.peer_fp === canonicalPeer
            && (canonicalOwner === null || row.owner_fp === canonicalOwner)) {
          store.delete(row.key);
          deleted += 1;
        }
      }
      await done;
      return deleted;
    } finally {
      db.close();
    }
  }

  async function clearChatOutboxForOwner(ownerFp) {
    const canonicalOwner = _canonicalSha256Fingerprint(
      ownerFp, "chat outbox cleanup owner",
    );
    const db = await _openMessagesDb();
    try {
      const tx = db.transaction(MSG_OUTBOX_STORE_NAME, "readwrite");
      const done = _messageDbTransactionDone(tx, "chat outbox owner cleanup");
      const store = tx.objectStore(MSG_OUTBOX_STORE_NAME);
      const rows = await _messageDbRequest(
        store.getAll(null, MSG_OUTBOX_MAX_TOTAL_ROWS),
        "chat outbox owner cleanup scan",
      );
      let deleted = 0;
      for (const row of rows || []) {
        if (row && row.owner_fp === canonicalOwner) {
          store.delete(row.key);
          deleted += 1;
        }
      }
      await done;
      return deleted;
    } finally {
      db.close();
    }
  }

