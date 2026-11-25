  // ── Phase 2: file send over daemon DC ─────────────────────────────
  // Chunked protocol: init → many chunk → complete. Server caps each
  // chunk at 16 KiB raw, files at 100MB. Cancel explicitly tells the
  // daemon to close, unlink, and unreserve the staging file; the idle
  // sweeper remains crash/disconnect fallback.
  //
  // 2026-05-23: chunk size was 64 KiB but the JSON envelope blew past
  // aiortc's 64 KiB SCTP max-message-size, closing the channel
  // mid-upload. 16 KiB raw → ~25 KiB envelope, safe everywhere.
  const _PHONE_FILE_MAX_BYTES = 100 * 1024 * 1024;
  const _PHONE_FILE_CHUNK_SIZE = 16 * 1024;
  const _PHONE_FILE_WINDOW_MAX_CHUNKS = 8;
  const _PHONE_FILE_WINDOW_MAX_BYTES = 128 * 1024;
  // SCTP send-buffer high-water mark. While bufferedAmount is above
  // this, hold off sending more chunks so the in-flight queue can
  // drain. Without throttling, a fast loop can flood the buffer and
  // the underlying stream blocks (or worse, the channel resets).
  const _PHONE_DC_BUFFER_HIGH = 256 * 1024;
  let _phoneFileUploadAborted = false;
  let _phoneFileUploadId = null;
  let _phoneFileUploadSession = null;

  function _bytesToBase64Url(bytes) {
    // Stream-friendly: btoa on a binary string, then convert to
    // URL-safe alphabet without padding (matches the server's
    // urlsafe_b64decode tolerant of missing padding).
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  async function _handleDaemonChatAttach() {
    $("#daemon-chat-file-input")?.click();
  }

  // Wait until the daemon DC's send buffer drops below the
  // high-water mark. Backpressure for the chunked upload loop —
  // without this a fast .send() loop can fill the SCTP buffer,
  // the underlying transport blocks, and (with bad luck) the
  // channel resets entirely. Caps wait at 5 s so a wedged channel
  // surfaces as an error instead of an infinite spin.
  async function _waitForDcDrain(session) {
    const dc = state.daemon_dc;
    if (!dc) throw new Error("no live daemon channel");
    const deadline = Date.now() + 5000;
    while (
      dc.bufferedAmount > _PHONE_DC_BUFFER_HIGH &&
      Date.now() < deadline &&
      !session.aborted
    ) {
      await new Promise((r) => setTimeout(r, 20));
    }
    if (session.aborted) throw new Error("cancelled");
    if (dc.bufferedAmount > _PHONE_DC_BUFFER_HIGH) {
      throw new Error("daemon channel send buffer did not drain");
    }
  }

  function _formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  }

  function _phoneFileResultOrThrow(result) {
    if (result && result.ok === false) {
      const error = new Error(
        result.reason || result.message || result.code || "file delivery failed",
      );
      error.code = result.code || "send_file_failed";
      error.reply = result;
      throw error;
    }
    return result;
  }

  async function _sendPhoneFileChunksWindowed(
    file,
    uploadId,
    initialOffset,
    chunkSize,
    session,
    onProgress,
  ) {
    let offset = initialOffset;
    let windowChunks = 2;
    while (offset < file.size) {
      if (session.aborted) throw new Error("cancelled");
      await _waitForDcDrain(session);
      const ranges = [];
      let cursor = offset;
      let windowBytes = 0;
      while (
        cursor < file.size &&
        ranges.length < windowChunks &&
        windowBytes < _PHONE_FILE_WINDOW_MAX_BYTES
      ) {
        const end = Math.min(cursor + chunkSize, file.size);
        const bytes = new Uint8Array(await file.slice(cursor, end).arrayBuffer());
        if (windowBytes && windowBytes + bytes.byteLength > _PHONE_FILE_WINDOW_MAX_BYTES) {
          break;
        }
        ranges.push({
          offset: cursor,
          end,
          data_b64: _bytesToBase64Url(bytes),
        });
        windowBytes += bytes.byteLength;
        cursor = end;
      }
      const replies = await Promise.all(ranges.map((range) =>
        _daemonRequestWithRetry("send_file_chunk", {
          upload_id: uploadId,
          offset: range.offset,
          data_b64: range.data_b64,
        }, {
          timeoutMs: 30_000,
          totalTimeoutMs: 180_000,
          maxAttempts: 5,
          shouldAbort: () => session.aborted,
        })
      ));
      let cumulative = offset;
      let retried = false;
      for (const reply of replies) {
        const received = Number(reply && reply.received_size);
        if (Number.isFinite(received)) cumulative = Math.max(cumulative, received);
        retried = retried || Number(reply && reply.retry_count) > 0;
      }
      const batchEnd = ranges[ranges.length - 1].end;
      if (cumulative < batchEnd) {
        throw new Error(`chunk acknowledgement stopped at ${cumulative}`);
      }
      offset = cumulative;
      windowChunks = retried
        ? Math.max(1, Math.floor(windowChunks / 2))
        : Math.min(_PHONE_FILE_WINDOW_MAX_CHUNKS, windowChunks + 1);
      onProgress(offset);
    }
    return offset;
  }

  async function _handleDaemonChatFilePicked(ev) {
    const peer = state.daemon_active_peer;
    if (!peer || !peer.fingerprint) return;
    const input = ev.target;
    const file = input && input.files && input.files[0];
    if (!file) return;
    // Reset the input so picking the same file twice in a row works.
    input.value = "";
    if (file.size > _PHONE_FILE_MAX_BYTES) {
      const sendStatus = $("#daemon-chat-send-status");
      sendStatus && (sendStatus.textContent =
        `File too large (${_formatBytes(file.size)}). Max 100 MiB.`);
      return;
    }
    if (_phoneFileUploadSession) {
      const sendStatus = $("#daemon-chat-send-status");
      sendStatus && (sendStatus.textContent =
        "Finish or cancel the current upload before attaching another file.");
      return;
    }
    _phoneFileUploadAborted = false;
    const session = {
      aborted: false,
      finalizing: false,
      uploadId: null,
      clientMsgId: _randomHexId(),
    };
    _phoneFileUploadSession = session;
    const progressEl = $("#daemon-chat-upload-progress");
    const nameEl = $("#daemon-chat-upload-name");
    const barEl = $("#daemon-chat-upload-bar");
    const detailEl = $("#daemon-chat-upload-detail");
    const sendStatus = $("#daemon-chat-send-status");
    if (nameEl) nameEl.textContent = file.name;
    if (barEl) barEl.style.width = "0%";
    if (detailEl) detailEl.textContent = `0 / ${_formatBytes(file.size)}`;
    if (progressEl) progressEl.style.display = "block";
    if (sendStatus) sendStatus.textContent = "";

    const log = $("#daemon-chat-log");
    const optimisticId = session.clientMsgId;
    _renderDaemonMessageBubble(log, {
      id: optimisticId,
      ts_ms: Date.now(),
      direction: "outbound",
      body: `📎 ${file.name} (${_formatBytes(file.size)})`,
      msg_type: "file",
    });
    if (log) log.scrollTop = log.scrollHeight;

    const intent = {
      peer_fp: peer.fingerprint,
      filename: file.name,
      mime: file.type || "application/octet-stream",
      size_bytes: file.size,
      client_msg_id: optimisticId,
    };
    try {
      let result = null;
      for (let recovery = 0; recovery < 6 && !result; recovery += 1) {
        if (session.aborted) throw new Error("cancelled");
        const initReply = await _daemonRequestWithRetry(
          "send_file_init",
          intent,
          {
            timeoutMs: 30_000,
            totalTimeoutMs: 180_000,
            maxAttempts: 5,
            shouldAbort: () => session.aborted,
          },
        );
        // A lost completion response is reconciled under the exact same
        // stable client key. The daemon can answer from durable accounting
        // without accepting a second byte or allocating another transfer.
        if (initReply && initReply.t === "send_file_result") {
          result = _phoneFileResultOrThrow(initReply);
          break;
        }
        const uploadId = initReply && initReply.upload_id;
        if (!uploadId) throw new Error("Upload init didn't return an upload_id.");
        const chunkSize = Math.min(
          Math.max(initReply.chunk_size || _PHONE_FILE_CHUNK_SIZE, 1024),
          _PHONE_FILE_CHUNK_SIZE,
        );
        const received = Number(initReply.received_size || 0);
        if (!Number.isInteger(received) || received < 0 || received > file.size) {
          throw new Error("Upload init returned an invalid resume offset.");
        }
        session.uploadId = uploadId;
        session.finalizing = false;
        _phoneFileUploadId = uploadId;
        try {
          await _sendPhoneFileChunksWindowed(
            file,
            uploadId,
            received,
            chunkSize,
            session,
            (offset) => {
              const pct = file.size
                ? Math.floor((offset / file.size) * 100)
                : 100;
              if (barEl) barEl.style.width = `${pct}%`;
              if (detailEl) {
                detailEl.textContent =
                  `${_formatBytes(offset)} / ${_formatBytes(file.size)} · ${pct}%`;
              }
            },
          );
        } catch (error) {
          if (session.aborted) throw new Error("cancelled");
          if (
            _isTransientDaemonRequestError(error) ||
            ["offset_mismatch", "unknown_upload", "upload_finalizing"]
              .includes(error && error.code)
          ) {
            if (detailEl) detailEl.textContent = "Restoring secure upload…";
            continue;
          }
          throw error;
        }

        if (detailEl) detailEl.textContent = "Finalizing…";
        session.finalizing = true;
        try {
          result = _phoneFileResultOrThrow(await _daemonRequest(
            "send_file_complete",
            {upload_id: uploadId},
            {timeoutMs: 60_000},
          ));
        } catch (error) {
          if (
            _isTransientDaemonRequestError(error) ||
            ["unknown_upload", "upload_finalizing"].includes(error && error.code)
          ) {
            if (detailEl) detailEl.textContent = "Confirming durable delivery…";
            continue;
          }
          throw error;
        }
      }
      if (!result) throw new Error("file delivery reconciliation budget exhausted");
      if (progressEl) progressEl.style.display = "none";
      if (result && result.background && result.accepted) {
        sendStatus && (sendStatus.textContent =
          "Securely staged. Sending in the background…");
      } else if (result && result.queued) {
        sendStatus && (sendStatus.textContent =
          "Peer is offline. File queued for delivery.");
      } else if (result && result.in_progress) {
        sendStatus && (sendStatus.textContent =
          "Securely staged. Delivery is being reconciled…");
      } else {
        sendStatus && (sendStatus.textContent = `Sent ${file.name}`);
      }
      // A durable queued/background admission intentionally returns before
      // the remote FILE_COMMIT. Keep the optimistic bubble visible until the
      // normal message/event refresh can replace it; an immediate fetch would
      // erase it during a healthy large transfer and look like a failed send.
      if (!(result && result.queued)) {
        try {
          const msgs = await fetchDaemonMessages(peer.fingerprint, 50);
          if (log) {
            log.innerHTML = "";
            for (const m of msgs) _renderDaemonMessageBubble(log, m);
            log.scrollTop = log.scrollHeight;
          }
        } catch (_e) { /* best-effort reconcile */ }
      }
    } catch (e) {
      if (progressEl) progressEl.style.display = "none";
      const reason = (e && e.message) || String(e);
      if (reason === "cancelled") {
        sendStatus && (sendStatus.textContent = "Upload cancelled.");
      } else {
        sendStatus && (sendStatus.textContent = `Upload failed: ${reason}`);
      }
      if (session.uploadId && !session.finalizing && !session.cancelRequested) {
        try {
          await _daemonRequestWithRetry(
            "send_file_cancel",
            {upload_id: session.uploadId},
            {timeoutMs: 10_000, totalTimeoutMs: 30_000, maxAttempts: 2},
          );
        } catch (_cancelError) { /* periodic sweeper is the fallback */ }
      }
    } finally {
      if (_phoneFileUploadSession === session) _phoneFileUploadSession = null;
      if (_phoneFileUploadId === session.uploadId) _phoneFileUploadId = null;
      _phoneFileUploadAborted = false;
    }
  }

  async function _handleDaemonChatUploadCancel() {
    const session = _phoneFileUploadSession;
    if (!session) return;
    const sendStatus = $("#daemon-chat-send-status");
    if (!session.uploadId) {
      session.aborted = true;
      _phoneFileUploadAborted = true;
      return;
    }
    if (session.finalizing) {
      try {
        await _daemonRequest("send_file_cancel", {upload_id: session.uploadId});
      } catch (error) {
        sendStatus && (sendStatus.textContent = error && error.code === "upload_finalizing"
          ? "Already finalizing; this upload can no longer be cancelled."
          : `Couldn't cancel: ${error && error.message ? error.message : error}`);
      }
      return;
    }
    session.aborted = true;
    session.cancelRequested = true;
    _phoneFileUploadAborted = true;
    try {
      await _daemonRequestWithRetry(
        "send_file_cancel",
        {upload_id: session.uploadId},
        {timeoutMs: 10_000, totalTimeoutMs: 30_000, maxAttempts: 2},
      );
    } catch (_error) { /* periodic sweeper remains the fallback */ }
  }

  $("#btn-daemon-chat-attach")?.addEventListener("click", _handleDaemonChatAttach);
  $("#daemon-chat-file-input")?.addEventListener("change", _handleDaemonChatFilePicked);
  $("#btn-daemon-chat-upload-cancel")?.addEventListener("click", _handleDaemonChatUploadCancel);

