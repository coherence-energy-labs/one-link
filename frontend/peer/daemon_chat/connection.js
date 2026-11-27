  let _phoneAutoReconnectInFlight = false;
  async function _attemptDcAutoReconnect() {
    if (_phoneAutoReconnectInFlight) return;
    if (!_hasExistingPairCert()) {
      // No cert to reconnect with — surface and bail.
      const sendStatus = $("#daemon-chat-send-status");
      if (sendStatus) {
        sendStatus.textContent =
          "Live link to the laptop dropped. Reload the page.";
      }
      return;
    }
    _phoneAutoReconnectInFlight = true;
    const sendStatus = $("#daemon-chat-send-status");
    if (sendStatus) sendStatus.textContent = "Reattaching…";
    try {
      const handoff = await _attemptReloginWithStoredCert();
      if (!handoff) {
        if (sendStatus) sendStatus.textContent =
          "Couldn't reconnect. Reload the page.";
        return;
      }
      await _runAutoPairFlow(handoff);
      if (sendStatus) sendStatus.textContent = "Reconnected.";
      // Refresh the chat view since stale message state may have
      // accumulated during the disconnect.
      const peer = state.daemon_active_peer;
      if (peer && peer.fingerprint) {
        try {
          const msgs = await fetchDaemonMessages(peer.fingerprint, 50);
          const log = $("#daemon-chat-log");
          if (log) {
            log.innerHTML = "";
            for (const m of msgs) _renderDaemonMessageBubble(log, m);
            log.scrollTop = log.scrollHeight;
          }
        } catch (_e) {}
      }
    } catch (e) {
      if (sendStatus) {
        sendStatus.textContent =
          `Couldn't reconnect: ${e && e.message ? e.message : e}. Reload.`;
      }
    } finally {
      _phoneAutoReconnectInFlight = false;
    }
  }

  function _routeDaemonDcMessage(raw, dc = state.daemon_dc) {
    let msg;
    try {
      msg = typeof raw === "string" ? JSON.parse(raw) : null;
    } catch { return; }
    if (!msg || msg.v !== "OL-PEER-1") return;
    if (msg.t === "identity_possession_challenge") {
      void _handleDaemonIdentityChallenge(msg, dc);
      return;
    }
    if (msg.t === "identity_possession_verified") {
      _handleDaemonIdentityVerified(msg, dc);
      return;
    }
    if (!dc || dc !== state.daemon_dc) return;
    // First, route to the existing browser-to-browser handlers
    // (pair/chat) — they're idempotent on non-matching version
    // tags but we still want to keep them wired for the case where
    // a browser-peer ALSO connects to this same page. In practice
    // a phone in pair-by-QR mode talks only to the daemon, but we
    // don't want to lose any v0.19.x dispatch coverage.
    const rid = msg.rid || "";
    if (rid && state.daemon_pending.has(rid)) {
      const pending = daemonLink.takePending(rid);
      clearTimeout(pending.timer);
      if (msg.t === "error") {
        const error = new Error(msg.message || msg.code || "daemon error");
        error.code = msg.code || "";
        error.reply = msg;
        pending.reject(error);
      } else {
        pending.resolve(msg);
      }
    }
  }

  function _daemonRequest(t, params, opts) {
    const dc = state.daemon_dc;
    if (!dc || dc.readyState !== "open") {
      return Promise.reject(new Error("no live daemon channel"));
    }
    const identityReady = state.daemon_identity_ready;
    if (
      !identityReady || identityReady.dc !== dc || !identityReady.verified
    ) {
      return Promise.reject(new Error("daemon identity is not verified"));
    }
    const rid = _genRid();
    const envelope = Object.assign(
      { v: "OL-PEER-1", t, rid },
      params || {},
    );
    const timeoutMs = (opts && opts.timeoutMs) || DAEMON_REQUEST_TIMEOUT_MS;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (daemonLink.dropPending(rid)) {
          reject(new Error(`${t} timed out after ${timeoutMs}ms`));
        }
      }, timeoutMs);
      daemonLink.addPending(rid, { resolve, reject, timer });
      try {
        dc.send(JSON.stringify(envelope));
      } catch (e) {
        daemonLink.dropPending(rid);
        clearTimeout(timer);
        reject(e);
      }
    });
  }

  function _isTransientDaemonRequestError(error) {
    if (error && error.code) return false;
    const message = String((error && error.message) || error || "").toLowerCase();
    return (
      message.includes("timed out") ||
      message.includes("channel closed") ||
      message.includes("no live daemon channel") ||
      message.includes("network") ||
      message.includes("send buffer") ||
      message.includes("acknowledgement stopped")
    );
  }

  async function _waitForLiveDaemonChannel(deadlineMs, shouldAbort) {
    while (Date.now() < deadlineMs) {
      if (shouldAbort && shouldAbort()) throw new Error("cancelled");
      const dc = state.daemon_dc;
      if (dc && dc.readyState === "open") return;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error("daemon channel did not reconnect before retry deadline");
  }

  async function _daemonRequestWithRetry(t, params, opts) {
    const options = opts || {};
    const maxAttempts = Math.max(1, Math.min(options.maxAttempts || 4, 8));
    const timeoutMs = Math.max(1000, options.timeoutMs || 30_000);
    const deadlineMs = Date.now() + Math.max(
      timeoutMs,
      options.totalTimeoutMs || 180_000,
    );
    let lastError = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      if (options.shouldAbort && options.shouldAbort()) {
        throw new Error("cancelled");
      }
      try {
        await _waitForLiveDaemonChannel(deadlineMs, options.shouldAbort);
        const reply = await _daemonRequest(t, params, {timeoutMs});
        reply.retry_count = attempt - 1;
        return reply;
      } catch (error) {
        lastError = error;
        if (
          !_isTransientDaemonRequestError(error) ||
          attempt >= maxAttempts ||
          Date.now() >= deadlineMs
        ) {
          throw error;
        }
        const delayMs = Math.min(1000, 100 * (2 ** (attempt - 1)));
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
    throw lastError || new Error(`${t} retry budget exhausted`);
  }

