  // Tier β - Reality Engine browser bridge.
  //
  // Every ATTEST_WINDOW_MS (default 1000) the browser hashes the
  // captured audio since the last attestation and POSTs the SHA-256
  // to the daemon as ``action: attest_frame``. The daemon signs the
  // hash with the device's Ed25519 identity key and ships a
  // CALL_FRAME_ATTEST to the peer. The peer's UI sees a fresh
  // Reality dot state every second.
  const ATTEST_WINDOW_MS = 1000;
  const attest = {
    recorder: null,         // MediaRecorder for outbound audio
    pendingChunks: [],      // accumulated Blob chunks for current window
    recentChunks: [],       // short in-memory pre-conversion ring buffer
    recentBytes: 0,
    windowStartMs: 0,
    timer: null,
  };
  const CAPSULE_CAPTURE_CHUNK_BYTES = 240 * 1024;
  const CAPSULE_CAPTURE_MAX_BYTES = 16 * 1024 * 1024;
  const CAPSULE_CAPTURE_RECENT_BYTES = 2 * 1024 * 1024;
  const CAPSULE_CAPTURE_RECENT_CHUNKS = 40;
  const CAPSULE_CAPTURE_MAX_MS = 60 * 1000;
  const capsuleCapture = {
    active: false,
    accepting: false,
    finalizing: false,
    callId: "",
    queuedChunks: 0,
    queuedBytes: 0,
    uploadedChunks: 0,
    uploadedBytes: 0,
    failed: false,
    failureMessage: "",
    pending: Promise.resolve(),
    maxTimer: null,
  };
  if (typeof window !== "undefined") window._oneLinkCapsuleCapture = capsuleCapture;

  function rememberRecentAudioChunk(blob) {
    if (!blob || !blob.size) return;
    attest.recentChunks.push(blob);
    attest.recentBytes += blob.size;
    while (
      attest.recentChunks.length > CAPSULE_CAPTURE_RECENT_CHUNKS ||
      attest.recentBytes > CAPSULE_CAPTURE_RECENT_BYTES
    ) {
      const removed = attest.recentChunks.shift();
      attest.recentBytes -= removed ? removed.size : 0;
    }
  }

  function capsuleChunkContentType(blob) {
    const base = String(blob?.type || attest.recorder?.mimeType || "")
      .split(";", 1)[0]
      .trim()
      .toLowerCase();
    return ["audio/webm", "audio/ogg", "audio/mp4"].includes(base)
      ? base
      : "application/octet-stream";
  }

  async function uploadCapsuleChunk(blob, sequence) {
    const contentType = capsuleChunkContentType(blob);
    let lastMessage = "Couldn't save one capsule segment.";
    for (let attempt = 0; attempt < 4; attempt += 1) {
      try {
        const response = await fetch(
          `/api/v1/calls/${encodeURIComponent(capsuleCapture.callId)}/capsule/chunk`,
          {
            method: "POST",
            headers: {
              "Content-Type": contentType,
              "X-One-Link-Capsule-Sequence": String(sequence),
            },
            body: blob,
            credentials: "same-origin",
            cache: "no-store",
          },
        );
        const result = await response.json().catch(() => ({}));
        if (response.ok && result.ok === true) return result;
        lastMessage = String(result.user_message || lastMessage);
        if (response.status >= 400 && response.status < 500 && response.status !== 408) {
          break;
        }
      } catch (_) {
        lastMessage = "Couldn't reach the daemon while saving the capsule.";
      }
      await new Promise((resolve) => setTimeout(resolve, 150 * (2 ** attempt)));
    }
    throw new Error(lastMessage);
  }

  function enqueueCapsuleBlob(blob) {
    if (!capsuleCapture.active || !capsuleCapture.accepting || !blob?.size) return;
    for (let offset = 0; offset < blob.size; offset += CAPSULE_CAPTURE_CHUNK_BYTES) {
      const part = blob.slice(
        offset,
        Math.min(blob.size, offset + CAPSULE_CAPTURE_CHUNK_BYTES),
        capsuleChunkContentType(blob),
      );
      if (capsuleCapture.queuedBytes + part.size > CAPSULE_CAPTURE_MAX_BYTES) {
        capsuleCapture.failed = true;
        capsuleCapture.failureMessage = "This capsule reached its safe size limit.";
        capsuleCapture.accepting = false;
        break;
      }
      const sequence = capsuleCapture.queuedChunks;
      capsuleCapture.queuedChunks += 1;
      capsuleCapture.queuedBytes += part.size;
      capsuleCapture.pending = capsuleCapture.pending.then(async () => {
        if (capsuleCapture.failed) return;
        try {
          await uploadCapsuleChunk(part, sequence);
          capsuleCapture.uploadedChunks += 1;
          capsuleCapture.uploadedBytes += part.size;
        } catch (error) {
          capsuleCapture.failed = true;
          capsuleCapture.accepting = false;
          capsuleCapture.failureMessage = String(
            error?.message || "Couldn't save the capsule audio.",
          );
          reportCallEvent("capsule_chunk_upload_failed", { ok: false });
        }
      });
    }
  }

  function resetCapsuleCapture() {
    if (capsuleCapture.maxTimer) clearTimeout(capsuleCapture.maxTimer);
    capsuleCapture.active = false;
    capsuleCapture.accepting = false;
    capsuleCapture.finalizing = false;
    capsuleCapture.callId = "";
    capsuleCapture.queuedChunks = 0;
    capsuleCapture.queuedBytes = 0;
    capsuleCapture.uploadedChunks = 0;
    capsuleCapture.uploadedBytes = 0;
    capsuleCapture.failed = false;
    capsuleCapture.failureMessage = "";
    capsuleCapture.pending = Promise.resolve();
    capsuleCapture.maxTimer = null;
    const endButton = $$("#btn-call-hangup");
    if (endButton) endButton.textContent = "End";
  }

  function beginCapsuleCapture(callId) {
    if (!callId) return false;
    if (capsuleCapture.active && capsuleCapture.callId === callId) return true;
    if (capsuleCapture.active) return false;
    resetCapsuleCapture();
    capsuleCapture.active = true;
    capsuleCapture.accepting = true;
    capsuleCapture.callId = callId;
    if (!attest.recorder && media.localStream) startAttestStream(media.localStream);
    const buffered = attest.recentChunks.slice();
    buffered.forEach(enqueueCapsuleBlob);
    // Detach outbound RTC immediately while preserving the local microphone
    // stream that feeds the explicit capsule capture rail.
    if (media.pc) {
      media.pc.getSenders().forEach((sender) => {
        try { sender.replaceTrack(null).catch(() => {}); } catch (_) {}
      });
      try { media.pc.close(); } catch (_) {}
      media.pc = null;
    }
    if (media.localStream) {
      media.localStream.getVideoTracks().forEach((track) => {
        try { track.stop(); } catch (_) {}
      });
    }
    const endButton = $$("#btn-call-hangup");
    if (endButton) endButton.textContent = "Save capsule";
    capsuleCapture.maxTimer = setTimeout(() => {
      finishCapsuleCapture("capture_limit").catch(() => {});
    }, CAPSULE_CAPTURE_MAX_MS);
    reportCallEvent("capsule_capture_started", { ok: true });
    return true;
  }

  async function finishCapsuleCapture(reason = "user_finished") {
    if (!capsuleCapture.active || capsuleCapture.finalizing) return false;
    capsuleCapture.finalizing = true;
    if (capsuleCapture.maxTimer) {
      clearTimeout(capsuleCapture.maxTimer);
      capsuleCapture.maxTimer = null;
    }
    try {
      if (attest.recorder?.state === "recording") {
        try { attest.recorder.requestData(); } catch (_) {}
        await new Promise((resolve) => setTimeout(resolve, 120));
      }
      capsuleCapture.accepting = false;
      await capsuleCapture.pending;
      if (capsuleCapture.failed) {
        throw new Error(capsuleCapture.failureMessage || "Couldn't save the capsule audio.");
      }
      if (!capsuleCapture.uploadedChunks || !capsuleCapture.uploadedBytes) {
        throw new Error("No microphone audio was available for this capsule.");
      }
      let result = null;
      for (let attempt = 0; attempt < 4; attempt += 1) {
        try {
          const response = await fetch(
            `/api/v1/calls/${encodeURIComponent(capsuleCapture.callId)}/capsule/finalize`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                expected_chunks: capsuleCapture.uploadedChunks,
                expected_bytes: capsuleCapture.uploadedBytes,
              }),
              credentials: "same-origin",
              cache: "no-store",
            },
          );
          result = await response.json().catch(() => ({}));
          if (response.ok && result.ok === true) break;
          if (response.status >= 400 && response.status < 500 && response.status !== 408) break;
        } catch (_) {
          result = null;
        }
        await new Promise((resolve) => setTimeout(resolve, 200 * (2 ** attempt)));
      }
      if (!result || result.ok !== true) {
        throw new Error(result?.user_message || "The capsule is saved locally and waiting to finish.");
      }
      const finishedCallId = capsuleCapture.callId;
      resetCapsuleCapture();
      stopAllMedia();
      hideActiveSurface();
      if (callUI.activeCallId === finishedCallId) callUI.activeCallId = null;
      callUI.activeCallPeerFp = null;
      callUI.activeCallLocalRole = "";
      reportCallEvent("capsule_capture_finalized", { reason, ok: true });
      return true;
    } catch (error) {
      capsuleCapture.finalizing = false;
      capsuleCapture.accepting = !capsuleCapture.failed;
      capsuleCapture.failureMessage = String(error?.message || "Couldn't finish the capsule.");
      if (typeof toast === "function") toast(capsuleCapture.failureMessage, "warn", 6000);
      reportCallEvent("capsule_capture_finalize_failed", { reason, ok: false });
      return false;
    }
  }
  if (typeof window !== "undefined") {
    window._beginOneLinkCapsuleCapture = beginCapsuleCapture;
    window._finishOneLinkCapsuleCapture = finishCapsuleCapture;
  }

  async function sha256HexFromBlobs(blobs) {
    // Concatenate the array of Blobs into one ArrayBuffer and SHA-256 it.
    const merged = new Blob(blobs);
    const buf = await merged.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", buf);
    const bytes = new Uint8Array(digest);
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  async function closeAttestWindow() {
    if (!callUI.activeCallId) return;
    if (!attest.pendingChunks.length) return;
    const chunks = attest.pendingChunks;
    attest.pendingChunks = [];
    try {
      const hex = await sha256HexFromBlobs(chunks);
      const tsUs = Date.now() * 1000;
      await callApiPost({
        action: "attest_frame",
        call_id: callUI.activeCallId,
        segment_hash_hex: hex,
        timestamp_us: tsUs,
        path_class: "lan",
        recording_state: "none",
      });
    } catch (_) {
      // Failure is non-fatal - the call continues, dot just stays grey.
    }
  }

  function startAttestStream(stream) {
    // MediaRecorder is the most browser-friendly way to get a stream
    // of opaque opus chunks we can hash. It uses ondataavailable
    // to emit Blobs at the timeslice cadence we pass. Successful setup
    // calls attest.recorder.start(200) after all callbacks are installed;
    // attest_recorder_start_failed remains a non-fatal telemetry event.
    if (!window.MediaRecorder || !stream) return;
    const audioTracks = stream.getAudioTracks ? stream.getAudioTracks() : [];
    if (!audioTracks.length) return;
    const audioStream = typeof MediaStream === "function"
      ? new MediaStream(audioTracks)
      : stream;
    const candidates = [
      "audio/webm;codecs=opus",
      "audio/ogg;codecs=opus",
      "audio/mp4",
    ];
    const mime = candidates.find((candidate) => {
      try { return MediaRecorder.isTypeSupported(candidate); } catch (_) { return false; }
    });
    try {
      attest.recorder = mime
        ? new MediaRecorder(audioStream, { mimeType: mime })
        : new MediaRecorder(audioStream);
    } catch (_) { return; }
    attest.recorder.ondataavailable = (ev) => {
      if (ev.data && ev.data.size > 0) {
        attest.pendingChunks.push(ev.data);
        rememberRecentAudioChunk(ev.data);
        if (capsuleCapture.active && capsuleCapture.accepting) {
          enqueueCapsuleBlob(ev.data);
        }
      }
    };
    try {
      attest.recorder.start(200);  // emit a chunk every 200ms
      attest.windowStartMs = Date.now();
      attest.timer = setInterval(closeAttestWindow, ATTEST_WINDOW_MS);
    } catch (_) {
      attest.recorder = null;
      reportCallEvent("attest_recorder_start_failed");
    }
  }

  function stopAttestStream() {
    if (attest.recorder) {
      try { attest.recorder.stop(); } catch (_) {}
      attest.recorder = null;
    }
    if (attest.timer) {
      clearInterval(attest.timer);
      attest.timer = null;
    }
    attest.pendingChunks = [];
    attest.recentChunks = [];
    attest.recentBytes = 0;
  }

