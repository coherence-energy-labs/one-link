  function ensureMediaTransceivers() {
    if (!media.pc || media.transceiversReady) return;
    try {
      const existing = (media.pc.getTransceivers ? media.pc.getTransceivers() : [])
        .map((t) => t && t.receiver && t.receiver.track && t.receiver.track.kind)
        .filter(Boolean);
      if (!existing.includes("audio") && media.pc.addTransceiver) {
        media.pc.addTransceiver("audio", { direction: "sendrecv" });
      }
      if (!existing.includes("video") && media.pc.addTransceiver) {
        media.pc.addTransceiver("video", { direction: "sendrecv" });
      }
      media.transceiversReady = true;
    } catch (_) {}
  }

  function bindRemoteVideoElementDiagnostics() {
    const v = $$("#call-remote-video");
    if (!v || v._oneLinkTraceBound) return;
    v._oneLinkTraceBound = true;
    const emit = (event) => {
      reportCallEvent(event, { media_kind: "video" });
      syncRemoteMediaSurface(event);
      reportCallMetricsOnce();
    };
    v.addEventListener("loadedmetadata", () => emit("remote_video_metadata"));
    v.addEventListener("resize", () => emit("remote_video_resize"));
    v.addEventListener("playing", () => emit("remote_video_playing"));
    v.addEventListener("waiting", () => emit("remote_video_waiting"));
    v.addEventListener("stalled", () => emit("remote_video_stalled"));
    v.addEventListener("error", () => emit("remote_video_error"));
  }

  async function applyAudioOutputDevice(audioEl) {
    if (!audioEl || !media.selectedAudioOutputId || typeof audioEl.setSinkId !== "function") return;
    try {
      await audioEl.setSinkId(media.selectedAudioOutputId);
      reportCallEvent("audio_output_changed");
    } catch (_) {
      reportCallEvent("audio_output_change_failed");
    }
  }

  async function refreshCallDevicePickers() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return;
    let devices = [];
    try { devices = await navigator.mediaDevices.enumerateDevices(); }
    catch (_) { return; }
    const groups = {
      audioinput: $$("#call-mic-select"),
      videoinput: $$("#call-camera-select"),
      audiooutput: $$("#call-speaker-select"),
    };
    const selected = {
      audioinput: media.selectedAudioInputId,
      videoinput: media.selectedVideoInputId,
      audiooutput: media.selectedAudioOutputId,
    };
    Object.entries(groups).forEach(([kind, select]) => {
      if (!select) return;
      const items = devices.filter((d) => d.kind === kind);
      const label = kind === "audioinput" ? "Default microphone"
        : kind === "videoinput" ? "Default camera"
        : "Default speaker";
      select.innerHTML = `<option value="">${label}</option>` + items.map((d, i) => {
        const text = d.label || `${label.replace("Default ", "")} ${i + 1}`;
        return `<option value="${escapeText(d.deviceId)}">${escapeText(text)}</option>`;
      }).join("");
      select.value = selected[kind] || "";
    });
  }

  async function replaceLocalMediaTracks(kind) {
    if (!media.localStream || !media.pc) return;
    const wantVideo = kind === "video";
    const constraints = wantVideo
      ? { audio: false, video: true }
      : { audio: true, video: false };
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia(buildMediaConstraints(constraints));
    } catch (_) {
      addOneCallEvent(`${wantVideo ? "Camera" : "Microphone"} could not switch.`);
      reportCallEvent(wantVideo ? "camera_change_failed" : "microphone_change_failed");
      return;
    }
    const newTrack = wantVideo ? stream.getVideoTracks()[0] : stream.getAudioTracks()[0];
    if (!newTrack) return;
    const oldTracks = wantVideo ? media.localStream.getVideoTracks() : media.localStream.getAudioTracks();
    oldTracks.forEach((t) => {
      try { media.localStream.removeTrack(t); } catch (_) {}
      try { t.stop(); } catch (_) {}
    });
    media.localStream.addTrack(newTrack);
    const sender = (media.pc.getSenders ? media.pc.getSenders() : [])
      .find((s) => s && s.track && s.track.kind === newTrack.kind);
    try {
      if (sender && sender.replaceTrack) await sender.replaceTrack(newTrack);
      else media.pc.addTrack(newTrack, media.localStream);
    } catch (_) {}
    if (wantVideo) newTrack.enabled = !media.cameraOff;
    else newTrack.enabled = !media.muted;
    attachLocalPreview(media.localStream);
    addOneCallEvent(`${wantVideo ? "Camera" : "Microphone"} switched.`);
    reportCallEvent(wantVideo ? "camera_changed" : "microphone_changed");
  }

  async function replaceOutgoingTrack(kind, newTrack) {
    if (!media.pc || !newTrack) return false;
    const sender = (media.pc.getSenders ? media.pc.getSenders() : [])
      .find((s) => s && s.track && s.track.kind === kind);
    try {
      if (sender && sender.replaceTrack) {
        await sender.replaceTrack(newTrack);
        return true;
      }
      if (media.localStream) {
        media.pc.addTrack(newTrack, media.localStream);
        return true;
      }
    } catch (_) {}
    return false;
  }

  async function toggleScreenShare() {
    if (!callUI.activeCallId || !media.pc) return;
    const surface = $$("#call-active-surface");
    const btn = $$("#btn-call-share-screen");
    if (media.screenSharing) {
      try { media.screenStream?.getTracks().forEach((t) => t.stop()); } catch (_) {}
      media.screenStream = null;
      const cameraTrack = media.cameraVideoTrack || media.localStream?.getVideoTracks()[0] || null;
      if (cameraTrack) await replaceOutgoingTrack("video", cameraTrack);
      media.screenSharing = false;
      surface?.classList.remove("screen-sharing");
      if (btn) {
        btn.textContent = "Share";
        btn.setAttribute("aria-pressed", "false");
      }
      addOneCallEvent("Screen sharing stopped.");
      reportCallEvent("screen_share_stopped");
      return;
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
      addOneCallEvent("Screen sharing is not available in this browser.");
      reportCallEvent("screen_share_unavailable");
      return;
    }
    try {
      const display = await navigator.mediaDevices.getDisplayMedia({
        video: true,
        audio: false,
      });
      const screenTrack = display.getVideoTracks()[0];
      if (!screenTrack) return;
      media.cameraVideoTrack = media.localStream?.getVideoTracks()[0] || null;
      media.screenStream = display;
      await replaceOutgoingTrack("video", screenTrack);
      media.screenSharing = true;
      screenTrack.onended = () => { toggleScreenShare().catch(() => {}); };
      surface?.classList.add("screen-sharing");
      if (btn) {
        btn.textContent = "Stop share";
        btn.setAttribute("aria-pressed", "true");
      }
      addOneCallEvent("Screen sharing started.");
      reportCallEvent("screen_share_started");
      sendLocalSdpOffer().catch(() => {});
    } catch (_) {
      addOneCallEvent("Screen sharing was cancelled.");
      reportCallEvent("screen_share_failed");
    }
  }

  async function openCallPictureInPicture() {
    const remote = $$("#call-remote-video");
    const local = $$("#call-local-video");
    const target = remote && remote.classList.contains("show") ? remote : local;
    if (!target || typeof target.requestPictureInPicture !== "function") {
      addOneCallEvent("Picture in Picture is not available here.");
      reportCallEvent("pip_unavailable");
      return;
    }
    try {
      await target.requestPictureInPicture();
      reportCallEvent("pip_started");
    } catch (_) {
      reportCallEvent("pip_failed");
    }
  }

  function toggleBackgroundBlur() {
    media.backgroundBlur = !media.backgroundBlur;
    const local = $$("#call-local-video");
    const btn = $$("#btn-call-blur");
    local?.classList.toggle("local-blur", media.backgroundBlur);
    if (btn) {
      btn.textContent = media.backgroundBlur ? "Clear preview" : "Blur preview";
      btn.setAttribute("aria-pressed", String(media.backgroundBlur));
    }
    reportCallEvent("background_blur_changed", {
      state: media.backgroundBlur ? "enabled" : "disabled",
    });
  }

  function renderParticipants() {
    const host = $$("#call-participants-list");
    if (!host) return;
    const localKinds = media.localStream
      ? media.localStream.getTracks().filter((t) => t.readyState === "live").map((t) => t.kind)
      : [];
    const remoteKinds = media.remoteStream
      ? media.remoteStream.getTracks().filter((t) => t.readyState === "live").map((t) => t.kind)
      : [];
    const localState = media.held ? "held" : localKinds.join("+") || "joining";
    const remoteState = remoteKinds.join("+") || "waiting";
    host.innerHTML = [
      `<div class="call-participant"><span>You</span><span>${escapeText(localState)}</span></div>`,
      `<div class="call-participant"><span>${escapeText(callUI.activeCallPeer || "Peer")}</span><span>${escapeText(remoteState)}</span></div>`,
    ].join("");
  }

  function renderLiveStats(metrics) {
    const host = $$("#call-stats-grid");
    if (!host || !metrics) return;
    const tau = callUI.tauLastDecision || null;
    host.innerHTML = [
      ["RTT", metrics.rtt_ms == null ? "--" : `${metrics.rtt_ms} ms`],
      ["Loss", metrics.loss_rate == null ? "--" : `${Math.round(metrics.loss_rate * 100)}%`],
      ["ICE", metrics.ice_connection_state || "--"],
      ["Video", metrics.remote_video_width ? `${metrics.remote_video_width}p` : "waiting"],
      ["Tau", tau ? `${Math.round(tau.coherence * 100)}%` : "--"],
      ["Load", tau ? targetMediaProfile(tau.targetLevel)?.name || "--" : "--"],
    ].map(([k, v]) => `<div><b>${escapeText(v)}</b>${escapeText(k)}</div>`).join("");
  }

  function setCallHold(on) {
    media.held = !!on;
    if (media.localStream) {
      media.localStream.getTracks().forEach((t) => {
        t.enabled = !media.held && (
          t.kind === "audio" ? !media.muted :
          t.kind === "video" ? !media.cameraOff :
          true
        );
      });
    }
    const surface = $$("#call-active-surface");
    surface?.classList.toggle("on-hold", media.held);
    const btn = $$("#btn-call-hold");
    if (btn) {
      btn.textContent = media.held ? "Resume" : "Hold";
      btn.setAttribute("aria-pressed", String(media.held));
    }
    addOneCallEvent(media.held ? "Call on hold." : "Call resumed.");
    reportCallEvent(media.held ? "call_hold_started" : "call_hold_ended");
    renderParticipants();
  }

  function cycleCallLayout() {
    const modes = ["focus", "split", "compact"];
    const next = modes[(modes.indexOf(media.layoutMode) + 1) % modes.length] || "focus";
    media.layoutMode = next;
    const surface = $$("#call-active-surface");
    if (surface) {
      surface.classList.toggle("layout-split", next === "split");
      surface.classList.toggle("layout-compact", next === "compact");
    }
    const btn = $$("#btn-call-layout");
    if (btn) btn.textContent = next === "focus" ? "Layout" : next;
    reportCallEvent("layout_changed", { reason: next });
  }

  function addTranscriptLine(text, who) {
    const host = $$("#call-transcript");
    if (!host || !text) return;
    const row = document.createElement("div");
    row.className = "call-transcript-line";
    row.textContent = `${who || "You"}: ${text}`;
    host.prepend(row);
    while (host.children.length > 12) host.removeChild(host.lastChild);
  }

  function _setCaptionsEnabled(enabled) {
    media.captionsOn = !!enabled;
    const btn = $$("#btn-call-captions");
    if (btn) btn.setAttribute("aria-pressed", String(media.captionsOn));
  }

  function _failActiveCaptions(recognizer, message, reason = "runtime") {
    if (media.captionRecognizer !== recognizer) return;
    media.captionRecognizer = null;
    media.captionsStarting = false;
    _setCaptionsEnabled(false);
    try { recognizer.abort(); } catch (_) {}
    addTranscriptLine(message, "One Link");
    reportCallEvent("captions_failed", { reason });
  }

  async function toggleCaptions() {
    const btn = $$("#btn-call-captions");
    if (media.captionsOn || media.captionsStarting) {
      media.captionsStarting = false;
      const active = media.captionRecognizer;
      media.captionRecognizer = null;
      _setCaptionsEnabled(false);
      try { active?.stop(); } catch (_) {}
      if (btn) btn.disabled = false;
      reportCallEvent("captions_stopped");
      return;
    }

    media.captionsStarting = true;
    _setCaptionsEnabled(false);
    if (btn) btn.disabled = true;
    try {
      // The legacy vendor-prefixed API may send microphone audio to a remote
      // recognition service.  One Link accepts only the standardized local
      // processing contract and never falls back to cloud recognition.
      const SpeechRecognition = window.SpeechRecognition;
      if (!SpeechRecognition) {
        throw new Error("This browser does not provide on-device captions.");
      }
      const rec = new SpeechRecognition();
      if (!("processLocally" in rec)) {
        throw new Error("This browser cannot guarantee local-only captions.");
      }
      rec.processLocally = true;
      if (rec.processLocally !== true) {
        throw new Error("The browser refused local-only caption processing.");
      }
      const language = document.documentElement.lang || navigator.language || "en-US";
      rec.lang = language;
      if (typeof SpeechRecognition.available === "function") {
        const availability = await SpeechRecognition.available({
          langs: [language],
          processLocally: true,
          quality: "conversation",
        });
        if (!media.captionsStarting) return;
        if (availability !== "available") {
          throw new Error(
            availability === "downloadable" || availability === "downloading"
              ? "Install the browser's on-device language pack before enabling captions."
              : "On-device captions are unavailable for this language.",
          );
        }
      }
      rec.continuous = true;
      rec.interimResults = true;
      rec.onresult = (ev) => {
        const results = Array.from(ev.results || []);
        const finalText = results
          .filter((r) => r.isFinal)
          .map((r) => r[0] && r[0].transcript)
          .filter(Boolean)
          .join(" ")
          .trim();
        if (finalText) addTranscriptLine(finalText, "You");
      };
      rec.onerror = (ev) => {
        _failActiveCaptions(
          rec,
          "On-device captions stopped. No audio was sent to a cloud recognizer.",
          ev?.error || "recognition_error",
        );
      };
      rec.onend = () => {
        if (media.captionsOn && media.captionRecognizer === rec) {
          try {
            rec.start();
          } catch (_) {
            _failActiveCaptions(
              rec,
              "On-device captions could not restart.",
              "restart_failed",
            );
          }
        }
      };
      media.captionRecognizer = rec;
      rec.start();
      media.captionsStarting = false;
      _setCaptionsEnabled(true);
      addTranscriptLine("On-device captions enabled.", "One Link");
      reportCallEvent("captions_started");
    } catch (error) {
      media.captionRecognizer = null;
      media.captionsStarting = false;
      _setCaptionsEnabled(false);
      const message = error && error.message
        ? error.message
        : "On-device captions could not start.";
      addTranscriptLine(`${message} No call audio was sent to a cloud recognizer.`, "One Link");
      reportCallEvent("captions_unavailable");
    } finally {
      if (btn) btn.disabled = false;
    }
  }

