  // ── Attach button + file picker ────────────────────────────────────
  const fileInput = $("#file-input");
  const triggerAttach = () => {
    if (!state.selectedPeer) { toast("Pick a device on the left to start.", "info"); return; }
    const peer = state.peers.get(state.selectedPeer);
    if (peer?.trust === "rejected") {
      toast("This device is blocked. Use Allow device first.", "bad");
      return;
    }
    fileInput.click();
  };
  // v0.21.x final: #btn-attach (header / mobile) keeps the direct
  // file-picker behaviour (one tap = one action on small screens).
  // #btn-attach2 (composer, desktop) opens the three-source popover
  // so File / Camera / Paste collapse into a single icon slot.
  $("#btn-attach").addEventListener("click", triggerAttach);
  $("#btn-attach2").addEventListener("click", (ev) => {
    ev.stopPropagation();
    _openAttachSourceMenu(ev.currentTarget);
  });
  function _openAttachSourceMenu(anchor) {
    if (!state.selectedPeer) {
      toast("Pick a device on the left to start.", "info");
      return;
    }
    const peer = state.peers.get(state.selectedPeer);
    if (peer?.trust === "rejected") {
      toast("This device is blocked. Use Allow device first.", "bad");
      return;
    }
    // Singleton: clicking the button again with the menu open dismisses.
    const existing = document.querySelector(".attach-source-menu");
    if (existing) { existing.remove(); return; }
    const menu = document.createElement("div");
    menu.className = "attach-source-menu";
    menu.setAttribute("role", "menu");
    menu.innerHTML = `
      <button type="button" class="asm-item" data-src="file">
        <span class="asm-icon">📁</span>
        <span class="asm-label">
          <span class="asm-title">File</span>
          <span class="asm-sub">Pick any file from this device</span>
        </span>
      </button>
      <button type="button" class="asm-item" data-src="camera">
        <span class="asm-icon">📸</span>
        <span class="asm-label">
          <span class="asm-title">Take a photo</span>
          <span class="asm-sub">Webcam preview + Snap</span>
        </span>
      </button>
      <button type="button" class="asm-item" data-src="paste">
        <span class="asm-icon">🖼️</span>
        <span class="asm-label">
          <span class="asm-title">Paste a screenshot</span>
          <span class="asm-sub">From clipboard (or just press Ctrl+V)</span>
        </span>
      </button>
      <button type="button" class="asm-item" data-src="folder">
        <span class="asm-icon">🗂️</span>
        <span class="asm-label">
          <span class="asm-title">Folder</span>
          <span class="asm-sub">Send an entire folder, one-shot</span>
        </span>
      </button>
    `;
    document.body.appendChild(menu);
    // Position above the anchor (composer button); flip below if no room.
    const r = anchor.getBoundingClientRect();
    // Measure after attach for correct height.
    const mh = menu.getBoundingClientRect().height;
    const above = r.top - mh - 8;
    if (above > 8) {
      menu.style.left = `${Math.max(8, r.left)}px`;
      menu.style.top = `${above}px`;
    } else {
      menu.style.left = `${Math.max(8, r.left)}px`;
      menu.style.top = `${r.bottom + 8}px`;
    }
    function close() {
      menu.remove();
      document.removeEventListener("click", off, true);
      document.removeEventListener("keydown", esc);
    }
    function off(ev) {
      if (!menu.contains(ev.target) && ev.target !== anchor) close();
    }
    function esc(ev) { if (ev.key === "Escape") close(); }
    menu.addEventListener("click", (ev) => {
      const btn = ev.target.closest(".asm-item");
      if (!btn) return;
      ev.stopPropagation();
      const src = btn.dataset.src;
      close();
      if (src === "file") {
        triggerAttach();
      } else if (src === "camera") {
        $("#btn-camera")?.click();
      } else if (src === "paste") {
        $("#btn-screenshot")?.click();
      } else if (src === "folder") {
        _triggerFolderAttach();
      }
    });
    setTimeout(() => {
      document.addEventListener("click", off, true);
      document.addEventListener("keydown", esc);
    }, 0);
  }
  // v0.21.x: chat composer "Folder" attach option — picks an OS
  // folder + opens the Send confirmation modal. Goes through the
  // ad-hoc folder-send endpoints (no Folders-tab registration
  // required).
  async function _triggerFolderAttach() {
    if (!state.selectedPeer) {
      toast("Pick a device on the left to start.", "info");
      return;
    }
    const peer = state.peers.get(state.selectedPeer);
    if (!peer?.fingerprint || peer.trust !== "pinned") {
      toast("Pick a paired device first.", "info");
      return;
    }
    let path = null;
    try {
      const r = await api.post("/api/fs/pick-folder", {});
      if (r && r.path) path = r.path;
      else if (r && r.cancelled) return;  // silent
    } catch (e) {
      toast(
        `Folder picker unavailable on this device: ${errorToastBody(e)}`,
        "info", 4000,
      );
      return;
    }
    if (!path) return;
    const leaf = path.split(/[\\/]/).filter(Boolean).pop() || path;
    openFolderSendConfirm({
      scope: "adhoc", ident: path,
      peerFp: peer.fingerprint,
      peerHostname: peer.hostname || peer.short_id,
      displayName: leaf, displayPath: path,
    });
  }

  // v0.9.2 voice - click toggles record / stop. Cancel + Send buttons
  // in the overlay handle explicit cancel vs send.
  $("#btn-voice")?.addEventListener("click", () => {
    if (state.voiceRec) {
      stopVoiceRecording({ cancel: false });
    } else {
      startVoiceRecording();
    }
  });
  // v0.21.x: composer emoji picker. Toggles open/close on click.
  $("#btn-emoji")?.addEventListener("click", (ev) => {
    ev.stopPropagation();
    openComposerEmojiPicker(ev.currentTarget);
  });
  $("#voice-cancel")?.addEventListener("click", () => {
    stopVoiceRecording({ cancel: true });
    toast("Recording discarded.", "info");
  });
  $("#voice-stop")?.addEventListener("click", () => {
    stopVoiceRecording({ cancel: false });
  });
  // Ctrl+Shift+M toggles record. Skipped when typing in an input
  // (so a chat-line literal "M" still types normally).
  document.addEventListener("keydown", (e) => {
    if (!(e.ctrlKey && e.shiftKey && (e.key === "M" || e.key === "m"))) return;
    const tag = (document.activeElement?.tagName || "").toLowerCase();
    if (tag === "textarea" || tag === "input") {
      // still allow if the chat composer is empty? simpler: allow always
      // since the chord is unlikely to be hit on accident.
    }
    e.preventDefault();
    if (state.voiceRec) stopVoiceRecording({ cancel: false });
    else startVoiceRecording();
  });
  // Screenshot button - reads clipboard image (e.g. from Win+Shift+S) and stages it.
  $("#btn-screenshot").addEventListener("click", async () => {
    if (!state.selectedPeer) { toast("Pick a device on the left to start.", "info"); return; }
    if (!navigator.clipboard?.read) {
      toast("This browser doesn't support clipboard read. Take a screenshot, then paste with Ctrl+V.", "info", 5000);
      return;
    }
    try {
      const items = await navigator.clipboard.read();
      let staged = 0;
      for (const item of items) {
        const imgType = item.types.find(t => t.startsWith("image/"));
        if (!imgType) continue;
        const blob = await item.getType(imgType);
        const ext = imgType.split("/")[1] || "png";
        const file = new File([blob], `screenshot-${Date.now()}.${ext}`, { type: imgType });
        await stageFile(file);
        staged++;
      }
      if (staged === 0) {
        toast("No image in clipboard. Use Win+Shift+S, then click 📷 again.", "info", 5000);
      }
    } catch (e) {
      toast(`Clipboard read failed: ${e.message || e}. You may need to grant permission.`, "bad", 6000);
    }
  });
  // v0.21.x camera capture button. Opens a modal that streams the
  // user's webcam to a video preview; Snap captures a JPEG and
  // stages it. On mobile (no getUserMedia) the file picker with
  // capture="environment" hits the OS camera app directly.
  $("#btn-camera")?.addEventListener("click", async () => {
    if (!state.selectedPeer) { toast("Pick a device on the left to start.", "info"); return; }
    if (!navigator.mediaDevices?.getUserMedia) {
      // Mobile fallback: native file picker with capture intent.
      const inp = document.createElement("input");
      inp.type = "file";
      inp.accept = "image/*";
      inp.capture = "environment";
      inp.onchange = () => {
        for (const f of inp.files || []) stageFile(f);
      };
      inp.click();
      return;
    }
    await openCameraCaptureModal();
  });
  async function openCameraCaptureModal() {
    _ensureCameraCaptureModal();
    const modal = document.getElementById("camera-capture-modal");
    const video = modal.querySelector(".ccm-video");
    const snapBtn = modal.querySelector(".ccm-snap");
    const closeBtn = modal.querySelector(".ccm-close");
    const swapBtn = modal.querySelector(".ccm-swap");
    let stream = null;
    let facingMode = "user";
    async function startStream(mode) {
      if (stream) {
        stream.getTracks().forEach((t) => { try { t.stop(); } catch {} });
        stream = null;
      }
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: mode || facingMode },
          audio: false,
        });
        video.srcObject = stream;
        await video.play().catch(() => {});
      } catch (e) {
        // v0.21.x: edge-case-specific friendly copy instead of raw
        // browser exception strings. Common causes: denied
        // permission, no camera attached, another app holding it.
        const why =
          e?.name === "NotAllowedError"
            ? "Camera permission denied. Allow it in your browser settings and try again."
          : e?.name === "NotFoundError"
            ? "No camera detected on this device. Plug one in or use a device with one."
          : e?.name === "NotReadableError"
            ? "Another app is using the camera right now. Close it and try again."
          : e?.name === "OverconstrainedError"
            ? "This camera doesn't support that resolution. Try again."
          : `Camera access failed: ${e?.message || e}`;
        toast(why, "bad", 6000);
        cleanup();
      }
    }
    function cleanup() {
      if (stream) {
        stream.getTracks().forEach((t) => { try { t.stop(); } catch {} });
        stream = null;
      }
      try { video.srcObject = null; } catch {}
      modal.classList.remove("show");
      document.body.classList.remove("ccm-open");
      snapBtn.removeEventListener("click", onSnap);
      closeBtn.removeEventListener("click", onClose);
      swapBtn.removeEventListener("click", onSwap);
      modal.removeEventListener("click", onBackdrop);
      document.removeEventListener("keydown", onKey);
    }
    async function onSnap() {
      if (!video.videoWidth) return;
      const canvas = document.createElement("canvas");
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(video, 0, 0);
      const blob = await new Promise((res) =>
        canvas.toBlob(res, "image/jpeg", 0.92));
      if (blob) {
        const file = new File([blob], `photo-${Date.now()}.jpg`, { type: "image/jpeg" });
        await stageFile(file);
        toast("Photo captured. Click Send when ready.", "good", 3000);
      }
      cleanup();
    }
    function onSwap() {
      facingMode = facingMode === "user" ? "environment" : "user";
      startStream(facingMode);
    }
    function onClose() { cleanup(); }
    function onBackdrop(ev) {
      const t = ev.target;
      if (t && t instanceof Element && t.hasAttribute("data-ccm-close")) cleanup();
    }
    function onKey(ev) {
      if (ev.key === "Escape") cleanup();
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); onSnap(); }
    }
    snapBtn.addEventListener("click", onSnap);
    closeBtn.addEventListener("click", onClose);
    swapBtn.addEventListener("click", onSwap);
    modal.addEventListener("click", onBackdrop);
    document.addEventListener("keydown", onKey);
    modal.classList.add("show");
    document.body.classList.add("ccm-open");
    await startStream(facingMode);
    setTimeout(() => snapBtn.focus(), 50);
  }
  function _ensureCameraCaptureModal() {
    if (document.getElementById("camera-capture-modal")) return;
    const m = document.createElement("div");
    m.id = "camera-capture-modal";
    m.className = "ccm-modal";
    m.setAttribute("role", "dialog");
    m.setAttribute("aria-modal", "true");
    m.setAttribute("aria-label", "Camera capture");
    m.innerHTML = `
      <div class="ccm-backdrop" data-ccm-close></div>
      <div class="ccm-pane">
        <video class="ccm-video" autoplay playsinline muted></video>
        <div class="ccm-actions">
          <button type="button" class="ccm-close">Cancel</button>
          <button type="button" class="ccm-swap" title="Switch camera" aria-label="Switch camera">↻</button>
          <button type="button" class="ccm-snap">Snap</button>
        </div>
      </div>
    `;
    document.body.appendChild(m);
  }
  $("#btn-unblock").addEventListener("click", async () => {
    const peer = state.selectedPeer ? state.peers.get(state.selectedPeer) : null;
    if (!peer?.fingerprint) return;
    await setTrust(peer.fingerprint, "pending");
    toast("Forgiveness granted. Pair it to send securely.", "good");
  });
  $("#btn-send-file-panel").addEventListener("click", triggerAttach);
  $("#btn-refresh-files").addEventListener("click", refreshFiles);
  $("#btn-open-inbox").addEventListener("click", async () => {
    // v0.9.7: Explorer windows can take a moment to render and
    // sometimes pop behind the browser; the user hits the button
    // and thinks nothing happened. Show an immediate toast so the
    // click is acknowledged.
    const t = toast("Opening inbox folder…", "info", 2500);
    try {
      const res = await api.post("/api/inbox/reveal", {});
      if (res?.throttled) {
        t?.remove?.();
        toast("Inbox is opening - check your taskbar.", "info", 2500);
      }
    } catch (e) {
      t?.remove?.();
      toast(`Open didn't work: ${e.message || e}`, "bad");
    }
  });
  document.querySelectorAll(".files-toggle button").forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll(".files-toggle button").forEach(x => x.classList.remove("active"));
      btn.classList.add("active");
      state.filesMode = btn.dataset.filesMode;
      if (state.filesMode === "sent") refreshTransfers();
      else refreshFiles();
      renderFilesPanel();
    };
  });
  fileInput.addEventListener("change", async (e) => {
    const files = Array.from(e.target.files || []);
    fileInput.value = "";
    for (const f of files) await stageFile(f);
  });

