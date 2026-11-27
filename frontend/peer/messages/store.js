  // ── v0.19.2 — message store + send/receive over control channel ─
  //
  // Wire protocol over the control DataChannel (post-pair only):
  //
  //   {"v":"OL-MSG-1", "t":"text", "id":"<uuid>",
  //    "body":"<utf-8 text>", "ts":<ms>}
  //
  //   {"v":"OL-MSG-1", "t":"ack", "id":"<uuid>", "ts":<ms>}
  //
  // IndexedDB layout: store `messages.v1` with composite-ish key
  // "<peer_fp>::<ts>::<id>" so per-peer reads sort cheaply by ts.
  // Each record: {id, peer_fp, direction, body, ts, received_ms,
  // ack_ms?}. Direction is "in" or "out". Outgoing rows track
  // ack_ms once the peer ack arrives.
  //
  // Why IDB: messages are an indexed list (by peer, by ts), not
  // a single blob. OPFS works for blobs; IDB works for sorted
  // indexed records. Both are origin-private + survive Clear-
  // Cookies.
  //
  // Direct-chat durability is intentionally independent from the daemon UI's
  // /api/send service-worker queue. An outbound control frame and its local
  // history row commit together here, stay bound to the exact local identity
  // and remote peer key, replay at most once per verified DataChannel session,
  // and leave the outbox only in the same transaction that records a durable
  // peer ACK. The receiver's exact (peer,id,payload) idempotency makes a
  // reconnect replay safe when the prior ACK was lost.

  const MSG_PROTOCOL_VERSION = "OL-MSG-1";
  const MSG_DB_NAME = "one-link-peer-messages";
  const MSG_STORE_NAME = "messages.v1";
  const MSG_OUTBOX_STORE_NAME = "outbox.v1";
  const MSG_QUARANTINE_STORE_NAME = "outbox-quarantine.v1";
  const MSG_DB_VERSION = 3;
  const MSG_BODY_MAX_BYTES = 64 * 1024;
  const MSG_MAX_ROWS_PER_PEER = 2000;
  const MSG_OUTBOX_MAX_ROWS_PER_PEER = 512;
  const MSG_OUTBOX_MAX_TOTAL_ROWS = 2000;
  const MSG_OUTBOX_SCAN_MAX = 2000;
  const MSG_OUTBOX_MAX_BATCHES_PER_DRAIN = 4;
  const MSG_OUTBOX_QUARANTINE_MAX_ROWS = 256;
  const MSG_OUTBOX_LOCK_NAME = "one-link.peer-chat-outbox.v1";
  const MSG_RATE_WINDOW_MS = 60 * 1000;
  const MSG_RATE_MAX_PER_PEER = 240;
  const MSG_FUTURE_SKEW_MS = 5 * 60 * 1000;

  function _newMessageId() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    // Fallback for very old browsers (we already require modern
    // crypto/OPFS, so this should never fire — defensive only).
    return bytesToB64Url(_randomBytes(16));
  }

  function _msgKey(peerFp, ts, id) {
    return `${peerFp || "unknown"}::${String(ts).padStart(15, "0")}::${id}`;
  }

  function _openMessagesDb() {
    return new Promise((resolve, reject) => {
      if (!window.indexedDB) {
        reject(new Error("IndexedDB unavailable"));
        return;
      }
      const req = indexedDB.open(MSG_DB_NAME, MSG_DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        let store;
        if (!db.objectStoreNames.contains(MSG_STORE_NAME)) {
          store = db.createObjectStore(MSG_STORE_NAME, { keyPath: "key" });
        } else {
          store = req.transaction.objectStore(MSG_STORE_NAME);
        }
        if (!store.indexNames.contains("by_peer_id")) {
          store.createIndex("by_peer_id", ["peer_fp", "id"], { unique: false });
        }
        if (!store.indexNames.contains("by_peer")) {
          store.createIndex("by_peer", "peer_fp", { unique: false });
        }
        let outbox;
        if (!db.objectStoreNames.contains(MSG_OUTBOX_STORE_NAME)) {
          outbox = db.createObjectStore(
            MSG_OUTBOX_STORE_NAME, { keyPath: "key" },
          );
        } else {
          outbox = req.transaction.objectStore(MSG_OUTBOX_STORE_NAME);
        }
        if (!outbox.indexNames.contains("by_owner_peer")) {
          outbox.createIndex(
            "by_owner_peer", ["owner_fp", "peer_fp"], { unique: false },
          );
        }
        if (!outbox.indexNames.contains("by_owner_peer_id")) {
          outbox.createIndex(
            "by_owner_peer_id", ["owner_fp", "peer_fp", "id"],
            { unique: true },
          );
        }
        if (!db.objectStoreNames.contains(MSG_QUARANTINE_STORE_NAME)) {
          db.createObjectStore(
            MSG_QUARANTINE_STORE_NAME,
            { keyPath: "quarantine_id", autoIncrement: true },
          );
        }
      };
      req.onerror = () => reject(req.error || new Error("IDB open failed"));
      req.onsuccess = () => resolve(req.result);
    });
  }

  function _validStoredMessageId(value) {
    return typeof value === "string"
      && value.length >= 8 && value.length <= 128
      && /^[A-Za-z0-9_-]+$/.test(value);
  }

  function _normalizeStoredMessage(rec) {
    if (!rec || typeof rec.peer_fp !== "string" || !rec.peer_fp
        || rec.peer_fp.length > 256 || !rec.id || !rec.ts) {
      throw new Error("message record requires peer_fp, id, ts");
    }
    if (!_validStoredMessageId(rec.id)) throw new Error("invalid message id");
    if (rec.direction !== "in" && rec.direction !== "out") {
      throw new Error("invalid message direction");
    }
    if (typeof rec.body !== "string" || !rec.body.length) {
      throw new Error("message body required");
    }
    if (new TextEncoder().encode(rec.body).byteLength > MSG_BODY_MAX_BYTES) {
      throw new Error(`message exceeds ${MSG_BODY_MAX_BYTES} bytes`);
    }
    if (!Number.isSafeInteger(rec.ts) || rec.ts <= 0
        || rec.ts > Date.now() + MSG_FUTURE_SKEW_MS) {
      throw new Error("invalid message timestamp");
    }
    return Object.assign({}, rec, {
      key: _msgKey(rec.peer_fp, rec.ts, rec.id),
    });
  }

  function _sameStoredMessage(a, b) {
    return Boolean(a && b)
      && a.peer_fp === b.peer_fp
      && a.id === b.id
      && a.direction === b.direction
      && a.body === b.body
      && a.ts === b.ts;
  }

  async function saveMessage(rec) {
    const row = _normalizeStoredMessage(rec);
    const db = await _openMessagesDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(MSG_STORE_NAME, "readwrite");
      const store = tx.objectStore(MSG_STORE_NAME);
      let result = null;
      let inserted = false;
      let failure = null;
      const existingReq = store.index("by_peer_id").getAll(
        IDBKeyRange.only([row.peer_fp, row.id]), 2,
      );
      existingReq.onerror = () => {
        failure = existingReq.error || new Error("IDB id lookup failed");
        tx.abort();
      };
      existingReq.onsuccess = () => {
        const matches = existingReq.result || [];
        if (matches.length > 1 || (matches.length === 1 &&
            !_sameStoredMessage(matches[0], row))) {
          failure = new Error("message id was reused for different content");
          tx.abort();
          return;
        }
        if (matches.length === 1) {
          result = matches[0];
          return;
        }
        const countReq = store.index("by_peer").count(row.peer_fp);
        countReq.onerror = () => {
          failure = countReq.error || new Error("IDB quota lookup failed");
          tx.abort();
        };
        countReq.onsuccess = () => {
          if (countReq.result >= MSG_MAX_ROWS_PER_PEER) {
            failure = new Error("browser chat history quota reached");
            tx.abort();
            return;
          }
          const addReq = store.add(row);
          addReq.onerror = () => {
            failure = addReq.error || new Error("IDB add failed");
          };
          addReq.onsuccess = () => {
            result = row;
            inserted = true;
          };
        };
      };
      tx.oncomplete = () => {
        db.close();
        resolve({ record: result, inserted });
      };
      tx.onabort = () => {
        db.close();
        reject(failure || tx.error || new Error("IDB message write aborted"));
      };
      tx.onerror = () => {
        failure = failure || tx.error || new Error("IDB message write failed");
      };
    });
  }

  async function getStoredMessage(peerFp, id) {
    if (typeof peerFp !== "string" || !peerFp || !_validStoredMessageId(id)) {
      throw new Error("invalid message lookup");
    }
    const db = await _openMessagesDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(MSG_STORE_NAME, "readonly");
      const req = tx.objectStore(MSG_STORE_NAME).index("by_peer_id").getAll(
        IDBKeyRange.only([peerFp, id]), 2,
      );
      req.onerror = () => reject(req.error || new Error("IDB message lookup failed"));
      req.onsuccess = () => {
        const matches = req.result || [];
        if (matches.length > 1) {
          reject(new Error("duplicate stored message ids"));
          return;
        }
        resolve(matches[0] || null);
      };
      tx.oncomplete = () => db.close();
      tx.onabort = () => { db.close(); reject(tx.error || new Error("IDB lookup aborted")); };
    });
  }

  async function markMessageAcked(peerFp, id, ackMs) {
    if (!_validStoredMessageId(id) || !Number.isSafeInteger(ackMs) || ackMs <= 0) {
      throw new Error("invalid message acknowledgement");
    }
    const db = await _openMessagesDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(MSG_STORE_NAME, "readwrite");
      const store = tx.objectStore(MSG_STORE_NAME);
      let result = null;
      let failure = null;
      const req = store.index("by_peer_id").getAll(
        IDBKeyRange.only([peerFp, id]), 2,
      );
      req.onerror = () => {
        failure = req.error || new Error("IDB ack lookup failed");
        tx.abort();
      };
      req.onsuccess = () => {
        const matches = req.result || [];
        if (matches.length !== 1 || matches[0].direction !== "out") {
          failure = new Error("ack does not bind to one outbound message");
          tx.abort();
          return;
        }
        const row = matches[0];
        if (!row.ack_ms) {
          row.ack_ms = ackMs;
          store.put(row);
        }
        result = row;
      };
      tx.oncomplete = () => { db.close(); resolve(result); };
      tx.onabort = () => {
        db.close();
        reject(failure || tx.error || new Error("IDB ack update aborted"));
      };
      tx.onerror = () => {
        failure = failure || tx.error || new Error("IDB ack update failed");
      };
    });
  }

  async function loadMessages(peerFp, opts) {
    opts = opts || {};
    const limit = Math.max(1, Math.min(Number(opts.limit || 200), MSG_MAX_ROWS_PER_PEER));
    const db = await _openMessagesDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(MSG_STORE_NAME, "readonly");
      const store = tx.objectStore(MSG_STORE_NAME);
      // Range over keys with the peer prefix. The composite-ish key
      // sorts by ts naturally because ts is zero-padded to 15 chars.
      const lower = `${peerFp}::`;
      const upper = `${peerFp}::￿`;
      const range = IDBKeyRange.bound(lower, upper);
      // Walk newest-first so the limit returns the latest messages, then
      // reverse for chronological rendering.
      const req = store.openCursor(range, "prev");
      const out = [];
      req.onerror = () => reject(req.error || new Error("IDB cursor failed"));
      req.onsuccess = () => {
        const cursor = req.result;
        if (!cursor) {
          resolve(out.reverse());
          return;
        }
        out.push(cursor.value);
        if (out.length >= limit) {
          resolve(out.reverse());
          return;
        }
        cursor.continue();
      };
      tx.oncomplete = () => db.close();
    });
  }

  async function clearMessages(peerFp) {
    const all = await loadMessages(peerFp, { limit: 100_000 });
    if (!all.length) return 0;
    const db = await _openMessagesDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(MSG_STORE_NAME, "readwrite");
      const store = tx.objectStore(MSG_STORE_NAME);
      let deleted = 0;
      tx.onerror = () => reject(tx.error || new Error("IDB clear failed"));
      tx.oncomplete = () => { db.close(); resolve(deleted); };
      for (const row of all) {
        store.delete(row.key);
        deleted++;
      }
    });
  }

