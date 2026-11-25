  function syncMuteCameraButtons() {
    const muteBtn = $$("#btn-call-mute");
    if (muteBtn) {
      muteBtn.setAttribute("aria-pressed", String(media.muted));
      muteBtn.textContent = media.muted ? "Unmute" : "Mute";
    }
    const camBtn = $$("#btn-call-camera");
    if (camBtn) {
      camBtn.setAttribute("aria-pressed", String(media.cameraOff));
      camBtn.textContent = media.cameraOff ? "Camera on" : "Camera";
    }
  }

  function setReconnectState(on, text) {
    // doctrine-ok: §3.2.a internal state class; visible copy stays repair-oriented.
    media.reconnecting = !!on;
    const surface = $$("#call-active-surface");
    const banner = $$("#call-reconnect-banner");
    surface?.classList.toggle("reconnecting", !!on);
    if (banner && text) banner.textContent = text;
    if (on) updateCallQuality("reconnecting");
  }

  function updateCallQuality(level, label) {
    const dot = $$("#call-quality-dot");
    const text = $$("#call-quality-text");
    if (dot) {
      // doctrine-ok: §3.2.a internal state class; visible copy stays repair-oriented.
      dot.classList.remove("fair", "bad", "reconnecting", "connecting");
      if (level && level !== "good") dot.classList.add(level);
    }
    if (text) {
      text.textContent = label || (
        level === "reconnecting" ? "Repairing media"
        : level === "bad" ? "Poor call quality"
        : level === "fair" ? "Fair call quality"
        : level === "connecting" ? "Connecting media"
        : "Good call quality"
      );
    }
    const chip = $$("#call-outgoing-quality-chip");
    if (chip && label) chip.textContent = label;
  }

  function renderCallHistory() {
    const host = $$("#call-history-list");
    if (!host) return;
    const rows = callUI.callHistory.slice(0, 5);
    if (!rows.length) {
      host.innerHTML = `<div class="call-history-item"><span>No recent calls</span><span>--</span></div>`;
      return;
    }
    host.innerHTML = rows.map((row) => (
      `<div class="call-history-item"><span>${escapeText(row.label)}</span><span>${escapeText(row.when)}</span></div>`
    )).join("");
  }

  function rememberCallHistory(label, outcome) {
    callUI.callHistory.unshift({
      label: `${outcome || "Call"} · ${label || callUI.activeCallPeer || "Device"}`,
      when: new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }),
    });
    callUI.callHistory = callUI.callHistory.slice(0, 10);
    renderCallHistory();
  }

  function toggleCallSettings(show) {
    const pane = $$("#call-settings-popover");
    const btn = $$("#btn-call-settings");
    const next = typeof show === "boolean" ? show : !(pane && pane.classList.contains("show"));
    if (pane) pane.classList.toggle("show", next);
    if (btn) btn.setAttribute("aria-expanded", String(next));
    if (next) refreshCallDevicePickers().catch(() => {});
  }

  $$("#btn-call-settings")?.addEventListener("click", () => toggleCallSettings());
  $$("#btn-call-settings-close")?.addEventListener("click", () => toggleCallSettings(false));
  $$("#btn-call-refresh-devices")?.addEventListener("click", () => refreshCallDevicePickers().catch(() => {}));
  $$("#btn-call-video-fit")?.addEventListener("click", () => {
    media.videoFit = media.videoFit === "contain" ? "cover" : "contain";
    const surface = $$("#call-active-surface");
    if (surface) surface.classList.toggle("video-fit-contain", media.videoFit === "contain");
    const btn = $$("#btn-call-video-fit");
    if (btn) btn.textContent = media.videoFit === "contain" ? "Fill video" : "Fit video";
    reportCallEvent("video_fit_changed", { reason: media.videoFit === "contain" ? "contain" : "cover" });
  });
  $$("#btn-call-blur")?.addEventListener("click", () => toggleBackgroundBlur());
  $$("#btn-call-share-screen")?.addEventListener("click", () => toggleScreenShare().catch(() => {}));
  $$("#btn-call-pip")?.addEventListener("click", () => openCallPictureInPicture().catch(() => {}));
  $$("#btn-call-hold")?.addEventListener("click", () => setCallHold(!media.held));
  $$("#btn-call-layout")?.addEventListener("click", () => cycleCallLayout());
  $$("#btn-call-captions")?.addEventListener("click", () => toggleCaptions());
  $$("#call-notes")?.addEventListener("input", (ev) => {
    callUI.callNotes = ev.target.value || "";
  });
  $$("#call-noise-select")?.addEventListener("change", async (ev) => {
    media.voiceProcessing = ev.target.value === "raw" ? "raw" : "smart";
    await replaceLocalMediaTracks("audio");
    reportCallEvent("voice_processing_changed", { state: media.voiceProcessing });
  });
  $$("#btn-call-copy-debug")?.addEventListener("click", async () => {
    try {
      const snapshot = await window._oneLinkCallDebug?.();
      await navigator.clipboard?.writeText(JSON.stringify(snapshot || {}, null, 2));
      addOneCallEvent("Call debug copied.");
      reportCallEvent("call_debug_copied");
    } catch (_) {
      addOneCallEvent("Call debug could not be copied.");
      reportCallEvent("call_debug_copy_failed");
    }
  });
  $$("#btn-call-export-trace")?.addEventListener("click", async () => {
    const callId = callUI.activeCallId;
    if (!callId) return;
    try {
      const [traceResp, localDebug] = await Promise.all([
        fetch(`/api/v1/calls/${encodeURIComponent(callId)}/trace`, {
          credentials: "include", cache: "no-store",
        }),
        window._oneLinkCallDebug?.().catch(() => null),
      ]);
      const trace = await traceResp.json();
      const payload = {
        exported_at_ms: Date.now(),
        call_id: callId,
        backend_trace: trace,
        local_debug: localDebug || null,
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: "application/json",
      });
      const a = document.createElement("a");
      const url = URL.createObjectURL(blob);
      a.href = url;
      a.download = `one-link-call-trace-${callId}-${new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19)}.json`;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        URL.revokeObjectURL(url);
        a.remove();
      }, 1000);
      addOneCallEvent("Call trace exported.");
      reportCallEvent("call_trace_exported", { ok: true });
    } catch (_) {
      addOneCallEvent("Call trace export failed.");
      reportCallEvent("call_trace_export_failed");
    }
  });
  $$("#btn-call-capsule")?.addEventListener("click", async () => {
    if (!callUI.activeCallId) return;
    const callId = callUI.activeCallId;
    const result = await callApiPost({
      action: "convert_to_async",
      call_id: callId,
    });
    if (!result || result.ok !== true || result.phase !== "async_capture") {
      if (typeof toast === "function") {
        toast(result?.user_message || "Capsule capture could not start.", "warn", 5000);
      }
      return;
    }
    beginCapsuleCapture(callId);
    updateOneChip("#call-one-engine", "Capsule");
    addOneCallEvent("Keep talking, then choose Save capsule when you're done.");
    reportCallEvent("voicemail_capsule_requested", { ok: true });
  });
  $$("#btn-call-group-upgrade")?.addEventListener("click", () => {
    addOneCallEvent("Group calling is staged; start a group thread to bring more people in.");
    reportCallEvent("group_call_requested");
  });
  $$("#btn-call-voicemail-instead")?.addEventListener("click", async () => {
    if (callUI.inboundCallId) {
      const callId = callUI.inboundCallId;
      hideIncomingRing();
      callUI.inboundCallId = null;
      await callApiPost({ action: "decline", call_id: callId });
      rememberCallHistory(callUI.inboundCallPeer, "Capsule");
    }
  });
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.addEventListener("message", (event) => {
      const data = event.data || {};
      if (data.type !== "call-notification-action") return;
      if (data.action === "accept-call") {
        if (data.call_id && callUI.inboundCallId === data.call_id) {
          acceptInboundCall().catch(() => {});
        } else {
          backfillLivingPresenceCalls().then(() => acceptInboundCall()).catch(() => {});
        }
      } else if (data.action === "message-peer") {
        hideIncomingRing();
        if (callUI.inboundCallId) {
          callApiPost({ action: "decline", call_id: callUI.inboundCallId }).catch(() => {});
          callUI.inboundCallId = null;
        }
        if (data.peer && typeof selectPeer === "function") selectPeer(data.peer);
        const composer = $$("#msg-input");
        if (composer) composer.focus();
      } else {
        backfillLivingPresenceCalls().catch(() => {});
      }
    });
  }
  $$("#call-mic-select")?.addEventListener("change", async (ev) => {
    media.selectedAudioInputId = ev.target.value || "";
    await replaceLocalMediaTracks("audio");
  });
  $$("#call-camera-select")?.addEventListener("change", async (ev) => {
    media.selectedVideoInputId = ev.target.value || "";
    await replaceLocalMediaTracks("video");
  });
  $$("#call-speaker-select")?.addEventListener("change", async (ev) => {
    media.selectedAudioOutputId = ev.target.value || "";
    await applyAudioOutputDevice($$("#call-remote-audio"));
  });
  if (navigator.mediaDevices && typeof navigator.mediaDevices.addEventListener === "function") {
    navigator.mediaDevices.addEventListener("devicechange", () => {
      refreshCallDevicePickers().catch(() => {});
      reportCallEvent("media_device_changed");
    });
  }

