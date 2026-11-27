  // ── Voice recording (v0.9.2) ───────────────────────────────────────
  // Uses MediaRecorder (browser-native opus/webm) + reuses the
  // existing /api/send-file pipeline. No new wire protocol - the
  // peer just receives a regular file send; renderFileBubble
  // recognizes audio extensions and renders a player inline.
  state.voiceRec = null;        // MediaRecorder instance
  state.voiceStream = null;     // active MediaStream (must be stopped)
  state.voiceChunks = [];       // collected blob fragments
  state.voiceStartedAt = 0;     // ms epoch
  state.voiceTimerId = null;    // setInterval handle for the live timer
  state.voiceCancelled = false; // sticky flag so onstop knows not to send
  state.voiceTargetPeer = null; // immutable peer captured when recording starts
  const COMPOSER_MIC_ICON = '<span class="composer-icon" aria-hidden="true">&#127908;</span>';
  const COMPOSER_STOP_ICON = '<span class="composer-icon" aria-hidden="true">&#9632;</span>';
  function setVoiceButtonIcon(recording = false) {
    const btn = $("#btn-voice");
    if (!btn) return;
    btn.innerHTML = recording ? COMPOSER_STOP_ICON : COMPOSER_MIC_ICON;
    btn.setAttribute(
      "aria-label",
      recording ? "Stop and preview voice recording" : "Record voice message",
    );
  }

  // Pick the most-supported opus container. Prefer webm/opus (Chrome
  // + Edge native), fall back to ogg/opus (Firefox), then plain
  // webm/ogg without explicit opus codec spec (Safari ≥ 14.1
  // exposes some MediaRecorder support but with audio/mp4).
  function _pickVoiceMime() {
    if (!("MediaRecorder" in window)) return null;
    const candidates = [
      "audio/webm;codecs=opus",
      "audio/ogg;codecs=opus",
      "audio/webm",
      "audio/ogg",
      "audio/mp4",
      "",
    ];
    for (const m of candidates) {
      try {
        if (m === "" || MediaRecorder.isTypeSupported(m)) return m;
      } catch { /* keep iterating */ }
    }
    return null;
  }

  function _voiceFilenameFor(mime) {
    const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    let ext = "webm";
    if (/ogg/.test(mime)) ext = "ogg";
    else if (/mp4/.test(mime)) ext = "m4a";
    return `voice-${ts}.${ext}`;
  }

  async function startVoiceRecording() {
    if (state.voiceRec) return;
    if (!state.selectedPeer) { toast("Pick a device on the left to start.", "info"); return; }
    const recordingPeer = state.selectedPeer;
    const peer = state.peers.get(state.selectedPeer);
    if (peer?.trust === "rejected") {
      toast("This device is blocked.", "bad");
      return;
    }
    const mime = _pickVoiceMime();
    if (mime === null) {
      toast("This browser doesn't support voice recording.", "warn", 6000);
      return;
    }
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch (e) {
      const why =
        e?.name === "NotAllowedError" ? "Microphone permission denied." :
        e?.name === "NotFoundError" ? "No microphone detected." :
        `Mic access failed: ${e?.message || e}`;
      toast(why, "bad", 6000);
      return;
    }
    let rec;
    try {
      rec = mime ? new MediaRecorder(stream, { mimeType: mime })
                 : new MediaRecorder(stream);
    } catch (e) {
      toast(`Recording failed to start: ${e?.message || e}`, "bad");
      stream.getTracks().forEach(t => t.stop());
      return;
    }
    state.voiceStream = stream;
    state.voiceRec = rec;
    state.voiceChunks = [];
    state.voiceStartedAt = Date.now();
    state.voiceCancelled = false;
    state.voiceTargetPeer = recordingPeer;
    rec.ondataavailable = (ev) => {
      if (ev.data && ev.data.size > 0) state.voiceChunks.push(ev.data);
    };
    rec.onstop = async () => {
      // Stop the underlying mic stream regardless of cancel/send.
      try { stream.getTracks().forEach(t => t.stop()); } catch {}
      stopVoiceTimer();
      $("#voice-overlay").style.display = "none";
      $("#btn-voice").classList.remove("recording");
      setVoiceButtonIcon(false);
      const wasCancelled = state.voiceCancelled;
      const chunks = state.voiceChunks;
      const recMime = rec.mimeType || mime || "audio/webm";
      const targetPeer = state.voiceTargetPeer;
      state.voiceRec = null;
      state.voiceStream = null;
      state.voiceChunks = [];
      state.voiceTargetPeer = null;
      if (wasCancelled || chunks.length === 0) return;
      const blob = new Blob(chunks, { type: recMime });
      // Minimum threshold - anything under 200ms is almost
      // certainly a misclick. Don't waste a peer-side bubble.
      if (blob.size < 1024) {
        toast("Voice clip was barely a syllable. Tossed.", "info");
        return;
      }
      // v0.21.x: preview-before-send. Instead of immediately
      // uploading, open a preview modal so the user can listen
      // back, re-record, or cancel. Power users can disable this
      // via state.runtimeSettings.voice_skip_preview.
      const skipPreview = state.runtimeSettings?.voice_skip_preview === true;
      if (skipPreview) {
        // _sendVoiceBlob sends through api.upload(...) so voice keeps transfer retry/resume behavior.
        await _sendVoiceBlob(blob, recMime, targetPeer);
      } else {
        openVoicePreviewModal(blob, recMime, targetPeer);
      }
    };
    try {
      rec.start();
    } catch (e) {
      toast(`Recording failed to start: ${e?.message || e}`, "bad");
      stream.getTracks().forEach(t => t.stop());
      state.voiceRec = null;
      state.voiceStream = null;
      state.voiceTargetPeer = null;
      return;
    }
    $("#btn-voice").classList.add("recording");
    setVoiceButtonIcon(true);
    $("#voice-overlay").style.display = "flex";
    $("#voice-timer").textContent = "0:00";
    state.voiceTimerId = setInterval(updateVoiceTimer, 250);
  }

  function stopVoiceRecording({ cancel = false } = {}) {
    if (!state.voiceRec) return;
    state.voiceCancelled = !!cancel;
    try { state.voiceRec.stop(); } catch {}
    // onstop handler does the rest.
  }

  function stopVoiceTimer() {
    if (state.voiceTimerId !== null) {
      clearInterval(state.voiceTimerId);
      state.voiceTimerId = null;
    }
  }
  function updateVoiceTimer() {
    if (!state.voiceStartedAt) return;
    const sec = Math.floor((Date.now() - state.voiceStartedAt) / 1000);
    const m = Math.floor(sec / 60);
    const s = sec - m * 60;
    $("#voice-timer").textContent = `${m}:${String(s).padStart(2, "0")}`;
    // Hard cap at 5 minutes to protect the channel.
    if (sec >= 300) {
      stopVoiceRecording({ cancel: false });
      toast("Voice clip capped at 5 minutes - sending now.", "info", 4000);
    }
  }

  // v0.21.x: voice playback speed. Click cycles through 1x → 1.5x
  // → 2x → 1x. Persisted in localStorage so the user's preferred
  // speed sticks across audio bubbles. Browser natively supports
  // arbitrary playbackRate values, including pitch preservation.
  const VOICE_SPEEDS = [1.0, 1.5, 2.0];
  const VOICE_SPEED_KEY = "one_link.voice_speed";
  function _getVoiceSpeed() {
    try {
      const v = parseFloat(localStorage.getItem(VOICE_SPEED_KEY) || "1");
      return VOICE_SPEEDS.includes(v) ? v : 1.0;
    } catch { return 1.0; }
  }
  function _setVoiceSpeed(v) {
    try { localStorage.setItem(VOICE_SPEED_KEY, String(v)); } catch {}
  }
  function _renderAudioSpeedButton(audio) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "audio-speed-btn";
    btn.title = "Change playback speed";
    const apply = (v) => {
      try {
        audio.playbackRate = v;
        if ("preservesPitch" in audio) audio.preservesPitch = true;
        else if ("mozPreservesPitch" in audio) audio.mozPreservesPitch = true;
        else if ("webkitPreservesPitch" in audio) audio.webkitPreservesPitch = true;
      } catch {}
      btn.textContent = v === 1.0 ? "1x" : (v === 1.5 ? "1.5x" : "2x");
      btn.dataset.speed = String(v);
    };
    apply(_getVoiceSpeed());
    btn.onclick = (ev) => {
      ev.stopPropagation();
      const cur = parseFloat(btn.dataset.speed || "1");
      const idx = VOICE_SPEEDS.indexOf(cur);
      const next = VOICE_SPEEDS[(idx + 1) % VOICE_SPEEDS.length];
      _setVoiceSpeed(next);
      apply(next);
    };
    return btn;
  }
  // v0.21.x: waveform background for audio bubbles. Decodes the
  // blob via Web Audio, samples peak amplitudes, draws bars. Cached
  // per-blob-hash so re-renders are cheap. Drawn as a CSS background
  // image on the audio-player wrap (the native controls remain
  // interactive — the waveform sits behind them).
  state.waveformCache = state.waveformCache || new Map();
  async function _renderWaveformBg(audio, src, wrap, blobHash) {
    if (!blobHash) return;
    const cached = state.waveformCache.get(blobHash);
    if (cached) { wrap.style.setProperty("--wf-bg", `url(${cached})`); wrap.classList.add("has-waveform"); return; }
    try {
      const resp = await fetch(src, { credentials: "same-origin" });
      if (!resp.ok) return;
      const buf = await resp.arrayBuffer();
      const ACtx = window.AudioContext || window.webkitAudioContext;
      if (!ACtx) return;
      const ctx = new ACtx();
      try {
        const decoded = await ctx.decodeAudioData(buf.slice(0));
        const dataUrl = _renderWaveformToDataUrl(decoded);
        state.waveformCache.set(blobHash, dataUrl);
        wrap.style.setProperty("--wf-bg", `url(${dataUrl})`);
        wrap.classList.add("has-waveform");
      } finally { try { ctx.close(); } catch {} }
    } catch (_) { /* silent: waveform is purely cosmetic */ }
  }
  function _renderWaveformToDataUrl(audioBuffer) {
    const W = 400, H = 48;
    const canvas = document.createElement("canvas");
    canvas.width = W; canvas.height = H;
    const cx = canvas.getContext("2d");
    cx.clearRect(0, 0, W, H);
    const data = audioBuffer.getChannelData(0);
    const bars = 100;
    const samplesPerBar = Math.max(1, Math.floor(data.length / bars));
    const barW = W / bars;
    cx.fillStyle = "rgba(255,255,255,.42)";
    for (let i = 0; i < bars; i++) {
      let peak = 0;
      for (let j = 0; j < samplesPerBar; j++) {
        const v = Math.abs(data[i * samplesPerBar + j] || 0);
        if (v > peak) peak = v;
      }
      const h = Math.max(2, peak * H * 0.9);
      cx.fillRect(i * barW + 1, (H - h) / 2, barW - 2, h);
    }
    return canvas.toDataURL("image/png");
  }

  // v0.21.x: preview-before-send modal for voice messages. Opens
  // after recording stops; user can listen back, re-record, send,
  // or discard. The "do this every time" experience matches
  // iMessage / WhatsApp behavior. Skip can be enabled per-user via
  // state.runtimeSettings.voice_skip_preview.
  function openVoicePreviewModal(blob, mime, targetPeer) {
    _ensureVoicePreviewModal();
    const modal = document.getElementById("voice-preview-modal");
    const audio = modal.querySelector(".vpm-audio");
    const sendBtn = modal.querySelector(".vpm-send");
    const reBtn = modal.querySelector(".vpm-rerec");
    const cancelBtn = modal.querySelector(".vpm-cancel");
    const sizeLabel = modal.querySelector(".vpm-size");
    const url = URL.createObjectURL(blob);
    audio.src = url;
    sizeLabel.textContent = fmtBytes(blob.size);
    function cleanup() {
      modal.classList.remove("show");
      document.body.classList.remove("vpm-open");
      try { audio.pause(); } catch {}
      try { audio.src = ""; } catch {}
      try { URL.revokeObjectURL(url); } catch {}
      sendBtn.removeEventListener("click", onSend);
      reBtn.removeEventListener("click", onRerec);
      cancelBtn.removeEventListener("click", onCancel);
      modal.removeEventListener("click", onBackdrop);
      document.removeEventListener("keydown", onKey);
    }
    async function onSend() {
      cleanup();
      await _sendVoiceBlob(blob, mime, targetPeer);
    }
    function onRerec() {
      cleanup();
      // Re-open the mic. Defer with a microtask so the cleanup
      // settles before getUserMedia kicks back on.
      Promise.resolve().then(() => startVoiceRecording());
    }
    function onCancel() {
      cleanup();
      toast("Voice clip discarded.", "info", 2500);
    }
    function onBackdrop(ev) {
      const t = ev.target;
      if (t && t instanceof Element && t.hasAttribute("data-vpm-close")) onCancel();
    }
    function onKey(ev) {
      if (ev.key === "Escape") onCancel();
      else if (ev.key === "Enter") onSend();
    }
    sendBtn.addEventListener("click", onSend);
    reBtn.addEventListener("click", onRerec);
    cancelBtn.addEventListener("click", onCancel);
    modal.addEventListener("click", onBackdrop);
    document.addEventListener("keydown", onKey);
    modal.classList.add("show");
    document.body.classList.add("vpm-open");
    setTimeout(() => sendBtn.focus(), 60);
  }
  function _ensureVoicePreviewModal() {
    if (document.getElementById("voice-preview-modal")) return;
    const m = document.createElement("div");
    m.id = "voice-preview-modal";
    m.className = "vpm-modal";
    m.setAttribute("role", "dialog");
    m.setAttribute("aria-modal", "true");
    m.setAttribute("aria-label", "Voice message preview");
    m.innerHTML = `
      <div class="vpm-backdrop" data-vpm-close></div>
      <div class="vpm-pane">
        <h2 class="vpm-title">Listen before you send</h2>
        <audio class="vpm-audio" controls></audio>
        <div class="vpm-meta">Clip size: <span class="vpm-size">--</span></div>
        <div class="vpm-actions">
          <button type="button" class="vpm-cancel">Discard</button>
          <button type="button" class="vpm-rerec">Re-record</button>
          <button type="button" class="vpm-send">Send</button>
        </div>
      </div>
    `;
    document.body.appendChild(m);
  }
  const _voiceUploadIntents = new WeakMap();
  async function _sendVoiceBlob(blob, mime, targetPeer = state.selectedPeer) {
    if (!blob || !targetPeer) {
      toast("Voice send needs a selected device.", "bad", 5000);
      return {_uploadFailed: true, error: "missing voice target"};
    }
    let intent = _voiceUploadIntents.get(blob);
    if (!intent) {
      const fname = _voiceFilenameFor(mime);
      intent = {
        peerId: targetPeer,
        file: new File([blob], fname, { type: mime }),
        clientDeliveryId: _newClientMsgId(),
        inFlight: null,
        completed: false,
        result: null,
      };
      _voiceUploadIntents.set(blob, intent);
    }
    if (intent.completed) return intent.result;
    if (intent.inFlight) return await intent.inFlight;
    const operation = (async () => {
      const sending = toast(`Sending voice message…`, "info", 30000);
      try {
        const result = await api.upload(intent.peerId, intent.file, {
          clientDeliveryId: intent.clientDeliveryId,
        });
        intent.completed = true;
        intent.result = result;
        return result;
      } catch (e) {
        toast(`Voice send failed: ${errorToastBody(e)}`, "bad");
        return {_uploadFailed: true, error: e};
      } finally {
        sending?.remove();
      }
    })();
    intent.inFlight = operation;
    try {
      return await operation;
    } finally {
      if (intent.inFlight === operation) intent.inFlight = null;
    }
  }

