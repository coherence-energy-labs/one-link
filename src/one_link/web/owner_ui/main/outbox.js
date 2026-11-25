  // ── Selection ──────────────────────────────────────────────────────
  // v0.14.0 - Service Worker registration + offline outbox.
  // Goal: a tab-blur during composition saves the draft + queues
  // any in-flight send into IDB. The browser's `sync` event drains
  // the queue when connectivity returns. The page also pokes the
  // SW with postMessage("drain-now") on every reconnect so the
  // user doesn't wait for the browser scheduler.
  //
  // Failure modes that fall back gracefully:
  //   - Browser without SW support (very old Safari): no SW, no
  //     IDB queue, sends behave exactly as v0.13. No regression.
  //   - SW registration denied (user setting): same.
  //   - IDB unavailable (private browsing locked-down): we still
  //     register the SW; the queue is in-memory; on tab close,
  //     pending sends are lost (degrades to v0.13 behavior).

  let _swReg = null;
  function _postOwnerAuthToServiceWorker(target) {
    const bearer = _ownerBearerToken();
    if (!target || !bearer) return;
    let persist = false;
    try {
      persist = localStorage.getItem(_PERSISTENT_OWNER_SESSION_KEY) === bearer;
    } catch (_) {}
    target.postMessage({ type: "owner-auth-v1", bearer, persist });
  }
  async function _registerServiceWorker() {
    if (!("serviceWorker" in navigator)) return;
    try {
      _swReg = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
      const ready = await navigator.serviceWorker.ready;
      _postOwnerAuthToServiceWorker(
        navigator.serviceWorker.controller || ready.active,
      );
    } catch (e) {
      console.warn("SW registration failed (degrading to no-SW path):", e);
    }
  }
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      _postOwnerAuthToServiceWorker(navigator.serviceWorker.controller);
    });
  }
  // Fire and forget; don't block init on registration.
  _registerServiceWorker();

  function _outboxOpenDB() {
    return new Promise((resolve, reject) => {
      if (!window.indexedDB) { reject(new Error("no-idb")); return; }
      const req = indexedDB.open("one-link-outbox-v1", 3);
      req.onupgradeneeded = (event) => {
        const db = req.result;
        let queue;
        if (!db.objectStoreNames.contains("queue")) {
          queue = db.createObjectStore(
            "queue", { keyPath: "id", autoIncrement: true },
          );
          queue.createIndex("dedupe_key", "dedupe_key", { unique: true });
        } else {
          queue = req.transaction.objectStore("queue");
          if (!queue.indexNames.contains("dedupe_key")) {
            queue.createIndex("dedupe_key", "dedupe_key", { unique: true });
          }
        }
        if (!db.objectStoreNames.contains("meta")) {
          db.createObjectStore("meta", { keyPath: "key" });
        }
        if (!db.objectStoreNames.contains("quarantine")) {
          db.createObjectStore(
            "quarantine", { keyPath: "quarantine_id", autoIncrement: true },
          );
        }
        if (event.oldVersion < 2) {
          const seen = new Map();
          const cursorReq = queue.openCursor();
          cursorReq.onsuccess = () => {
            const cursor = cursorReq.result;
            if (!cursor) return;
            const queued = cursor.value || {};
            let oldClientId = "";
            try {
              const parsed = JSON.parse(queued.body || "null");
              oldClientId = parsed && typeof parsed.client_msg_id === "string"
                ? parsed.client_msg_id : "";
            } catch (_) {}
            let dedupeKey = /^[A-Za-z0-9_-]{8,128}$/.test(oldClientId)
              ? `send:${oldClientId.toLowerCase()}`
              : `legacy:${String(cursor.primaryKey)}`;
            const prior = seen.get(dedupeKey);
            if (prior && prior.url === queued.url && prior.method === queued.method
                && prior.body === queued.body) {
              cursor.delete();
            } else {
              if (prior) dedupeKey = `legacy-conflict:${String(cursor.primaryKey)}`;
              seen.set(dedupeKey, queued);
              cursor.update({
                ...queued,
                method: queued.method || "POST",
                dedupe_key: dedupeKey,
              });
            }
            cursor.continue();
          };
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  const _OUTBOX_MAX_ROWS = 2000;
  const _OUTBOX_MAX_ENVELOPE_BYTES = 128 * 1024;
  const _OUTBOX_MAX_TEXT_BYTES = 64 * 1024;
  const _OUTBOX_SEND_FIELDS = new Set([
    "peer", "body", "queue_on_failure", "reply_to", "client_msg_id",
  ]);
  function _outboxFailure(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
  }
  function _validatedOutboxSend(item) {
    if (!item || item.url !== "/api/send" || item.method !== "POST"
        || typeof item.body !== "string"
        || new TextEncoder().encode(item.body).byteLength
          > _OUTBOX_MAX_ENVELOPE_BYTES) {
      throw _outboxFailure("OUTBOX_INVALID", "invalid queued send envelope");
    }
    let payload;
    try {
      payload = JSON.parse(item.body);
    } catch {
      throw _outboxFailure("OUTBOX_INVALID", "queued send body is not JSON");
    }
    if (!payload || Array.isArray(payload) || typeof payload !== "object"
        || Object.keys(payload).some((key) => !_OUTBOX_SEND_FIELDS.has(key))) {
      throw _outboxFailure("OUTBOX_INVALID", "queued send has unsupported fields");
    }
    const clientId = payload.client_msg_id;
    if (typeof clientId !== "string"
        || !/^[A-Za-z0-9_-]{8,128}$/.test(clientId)
        || typeof payload.peer !== "string" || !payload.peer.trim()
        || payload.peer.length > 256
        || typeof payload.body !== "string" || !payload.body.trim()
        || new TextEncoder().encode(payload.body).byteLength
          > _OUTBOX_MAX_TEXT_BYTES
        || (payload.queue_on_failure !== undefined
          && typeof payload.queue_on_failure !== "boolean")
        || (payload.reply_to !== undefined && payload.reply_to !== null
          && (typeof payload.reply_to !== "string"
            || !/^[A-Za-z0-9_-]{8,128}$/.test(payload.reply_to)))) {
      throw _outboxFailure("OUTBOX_INVALID", "queued send fields are invalid");
    }
    return { payload, clientId };
  }
  async function _outboxQueue(item) {
    try {
      const { clientId } = _validatedOutboxSend(item);
      const queuedItem = {
        ...item,
        method: "POST",
        dedupe_key: `send:${clientId.toLowerCase()}`,
      };
      const db = await _outboxOpenDB();
      const tx = db.transaction("queue", "readwrite");
      const store = tx.objectStore("queue");
      let rejection = null;
      const existingReq = store.index("dedupe_key").get(queuedItem.dedupe_key);
      existingReq.onsuccess = () => {
        const existing = existingReq.result;
        if (existing) {
          if (
            existing.url !== queuedItem.url
            || existing.method !== queuedItem.method
            || existing.body !== queuedItem.body
          ) {
            rejection = _outboxFailure(
              "OUTBOX_CONFLICT",
              "client_msg_id was already queued with a different payload",
            );
            tx.abort();
          }
          return;
        }
        const countReq = store.count();
        countReq.onsuccess = () => {
          if (countReq.result >= _OUTBOX_MAX_ROWS) {
            rejection = _outboxFailure(
              "OUTBOX_QUOTA", "offline send queue is full",
            );
            tx.abort();
            return;
          }
          store.add(queuedItem);
        };
      };
      return new Promise((res, rej) => {
        tx.oncomplete = () => { db.close(); res(true); };
        tx.onabort = () => {
          db.close();
          rej(rejection || tx.error || new Error("outbox transaction aborted"));
        };
        tx.onerror = () => {
          // onabort owns closing the database and returning the most specific
          // failure because IndexedDB normally follows an error with abort.
          if (!rejection && tx.error) rejection = tx.error;
        };
      });
    } catch (error) {
      if (["OUTBOX_INVALID", "OUTBOX_CONFLICT", "OUTBOX_QUOTA"]
        .includes(error?.code)) {
        throw error;
      }
      console.warn("Offline outbox unavailable:", error);
      return false;
    }
  }
  async function _outboxRequestSync() {
    if (!_swReg) return;
    try {
      if ("sync" in _swReg) {
        await _swReg.sync.register("ol-outbox");
      } else {
        // Fallback for browsers without Background Sync API: just
        // postMessage to the SW so it tries draining now.
        navigator.serviceWorker?.controller?.postMessage({ type: "drain-now" });
      }
    } catch {}
  }

  // Wrap api.post so a network failure on /api/send queues into IDB
  // for later. Called explicitly from sendCurrent - we don't want to
  // queue arbitrary failed POSTs (that would queue auth refreshes,
  // settings saves, etc.). Outbox is for sends ONLY.
  async function _sendWithOutbox(path, body, opts = {}) {
    try {
      return await api.post(path, body, opts);
    } catch (e) {
      // v0.21.x: AbortError from the new api.post timeoutMs feature
      // is treated as network-like so the local outbox catches it
      // instead of bubbling up as a generic "failed" toast. The
      // user is told their message is queued and will send when
      // connectivity returns — never a silent disabled button.
      const errStr = String(e?.message || e);
      const isAbort = e?.name === "AbortError" || /aborted|AbortError/i.test(errStr);
      const isNetworkLike =
        isAbort
        || /Failed to fetch|NetworkError|TypeError/i.test(errStr);
      if (!isNetworkLike) throw e;
      // Network looks broken; queue the payload.
      const queued = await _outboxQueue({
        url: path,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        queuedAt: Date.now(),
      });
      if (queued) {
        await _outboxRequestSync();
        if (isAbort) {
          toast(
            "Send took too long. Queued; will retry in the background.",
            "info", 5000,
          );
        } else {
          toast(
            "No connection. Queued; will send when you're back online.",
            "info", 4000,
          );
        }
        return { ok: true, queued: true, reason: isAbort ? "client_timeout" : "offline" };
      }
      throw e;
    }
  }

  // v0.21.x bulletproof send: random 32-char hex id so the browser
  // can paint an optimistic outbound bubble immediately and the
  // daemon's echoed event reconciles via id-match. Matches the
  // daemon's uuid4().hex shape exactly.
  function _newClientMsgId() {
    const raw = (typeof crypto !== "undefined" && crypto.randomUUID)
      ? crypto.randomUUID()
      : _fallbackUuid4Hyphenated();
    return raw.replace(/-/g, "");
  }
  function _fallbackUuid4Hyphenated() {
    const b = new Uint8Array(16);
    (crypto || self.msCrypto).getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
    return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20,32)}`;
  }
  // v0.21.x: update one outbound bubble's send-state. Used by
  // sendCurrent on resolve and by the inline Retry button. Re-
  // renders only if the affected message is in the active thread.
  function _markBubbleState(msgId, sendingState, extras = {}) {
    const idx = state.messages.findIndex(x => x.id === msgId);
    if (idx < 0) return;
    // 2026-05-22 audit Batch AA: don't overwrite send-state on a
    // message that was already deleted out from under us — that
    // would render "[message deleted]" with a ✓ "sent" tick.
    // Both ``deleted_at_ms`` (server-side delete) and a body of
    // ``[message deleted]`` (legacy client-side flag) are signals
    // that the message has been tombstoned; don't decorate it.
    const current = state.messages[idx];
    if (current.deleted_at_ms || current.body === "[message deleted]") {
      return;
    }
    state.messages[idx] = {
      ...current,
      _sendingState: sendingState,
      ...extras,
    };
    if (state.messages[idx].peer === state.selectedPeer) renderMessages();
  }
  // v0.21.x: render the per-bubble send-state pill (Sending… /
  // Queued / Failed · Retry). Lives inline at the bottom of the
  // bubble so the status is anchored to the message, not to a
  // toast that disappears in 4s.
  function renderSendStatePill(msg) {
    const wrap = el("span", `send-pill send-pill-${msg._sendingState}`);
    if (msg._sendingState === "sending") {
      wrap.appendChild(el("span", "send-dot"));
      wrap.appendChild(document.createTextNode(" Sending…"));
    } else if (msg._sendingState === "queued") {
      // Prefer the daemon's user-facing copy when present — it
      // explains the actual wire-path state (handshake, ratchet
      // desync, peer unreachable…) rather than the vague "path is
      // healthy" line that confused users when presence said online.
      let reasonHint;
      if (msg._queueDetail) {
        reasonHint = msg._queueDetail;
      } else if (msg._queueReason === "client_timeout") {
        reasonHint = "Send took longer than expected";
      } else if (msg._queueReason === "peer_offline") {
        reasonHint = "Other device is offline";
      } else if (msg._queueReason === "peer_unreachable") {
        reasonHint = "Other device is not reachable right now";
      } else if (msg._queueReason === "handshake_failed") {
        reasonHint = "Re-establishing secure session";
      } else if (msg._queueReason === "timeout") {
        reasonHint = "Other device didn't respond in time";
      } else if (msg._queueReason === "secure_session_desync") {
        reasonHint = "Refreshing secure session";
      } else {
        reasonHint = "Will send when the path is healthy";
      }
      wrap.appendChild(document.createTextNode(`Queued - ${reasonHint}`));
      // Inline "Retry now" so impatient users don't have to wait on
      // the daemon's heal-and-drain loop. Re-uses the same retrySend
      // path the Failed state uses, so the state machine stays
      // single-source.
      wrap.appendChild(document.createTextNode(" - "));
      const retryNow = document.createElement("button");
      retryNow.type = "button";
      retryNow.className = "send-retry";
      retryNow.textContent = "Retry now";
      retryNow.onclick = (ev) => {
        ev.stopPropagation();
        retrySend(msg.id);
      };
      wrap.appendChild(retryNow);
    } else if (msg._sendingState === "failed") {
      const txt = msg._error || "Failed to send";
      wrap.appendChild(document.createTextNode(`${txt} - `));
      const retry = document.createElement("button");
      retry.type = "button";
      retry.className = "send-retry";
      retry.textContent = "Retry";
      retry.onclick = (ev) => {
        ev.stopPropagation();
        retrySend(msg.id);
      };
      wrap.appendChild(retry);
    }
    return wrap;
  }
  // v0.21.x: re-attempt a failed send. Reuses the original body and
  // peer; resets the bubble back to "sending" state so the user sees
  // it pick up where it stopped.
  async function retrySend(msgId) {
    const idx = state.messages.findIndex(x => x.id === msgId);
    if (idx < 0) return;
    const prev = state.messages[idx];
    if (!prev || prev.t !== "TEXT" || !prev.body) return;
    const peer = state.peers.get(prev.peer);
    if (!peer) {
      toast("That device just dropped off the network. Try again later.", "info", 5000);
      return;
    }
    _markBubbleState(msgId, "sending", {
      _error: undefined,
      _attempts: (prev._attempts || 1) + 1,
    });
    if (prev.peer === state.selectedPeer) _forceNextMessagesToBottom();
    const sendBody = {
      peer: prev.peer,
      body: prev.body,
      client_msg_id: prev.id,
    };
    if (prev.reply_to) sendBody.reply_to = prev.reply_to;
    try {
      const result = await _sendWithOutbox(
        "/api/send", sendBody, { timeoutMs: 25000 },
      );
      if (result && result.ok === false) {
        _markBubbleState(msgId, "failed", {
          _error: result.user_message || result.error || "Message couldn't be sent.",
        });
      } else if (result && result.queued) {
        const tx = result.after_failure || {};
        _markBubbleState(msgId, "queued", {
          _queueReason: result.reason || null,
          _queueDetail: tx.error || null,
          _queueHint: tx.hint || null,
        });
      } else {
        _markBubbleState(msgId, "sent");
      }
    } catch (e) {
      _markBubbleState(msgId, "failed", { _error: errorToastBody(e) });
    }
  }
  // v0.15.1 - Offline indicator. Reads navigator.onLine at boot
  // + listens for online/offline events. The banner is calm copy
  // ("messages queue and send when you're back") so a flaky cafe
  // Wi-Fi doesn't read as something being broken. We deliberately
  // keep it on a separate channel from the toast stack so a long
  // offline interval doesn't clutter the toast surface; the banner
  // sits above main and stays as long as offline persists.
  function _applyOnlineState(online) {
    const b = document.querySelector("#offline-banner");
    if (!b) return;
    b.classList.toggle("show", !online);
  }
  // Apply at boot - navigator.onLine is set by the time scripts run.
  _applyOnlineState(navigator.onLine !== false);
  window.addEventListener("offline", () => {
    _applyOnlineState(false);
  });
  // When the page comes back online, poke the SW to drain.
  window.addEventListener("online", () => {
    _applyOnlineState(true);
    _outboxRequestSync();
    // Brief acknowledgement toast so the user knows queued sends
    // are draining, then the banner disappears. Short duration so
    // it doesn't linger if connectivity flaps repeatedly.
    toast("Back online. Sending queued messages.", "good", 3000);
  });

  // v0.14.0 - Frame-budget instrumentation. Records the duration
  // of selected hot operations into a capped ring buffer. CI / the
  // diagnostics overlay can read state.frameBudget to verify SLAs
  // (renderMessages within 16.7ms, conversation-switch within
  // 150ms, etc.). Cheap: each measurement is a high-precision
  // timestamp diff.
  state.frameBudget = state.frameBudget || {
    renderMessages: [],   // ring buffer of durations in ms
    selectPeer: [],
    selectGroup: [],
    capacity: 200,        // last N samples
  };
