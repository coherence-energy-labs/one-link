  // ── Tier α media - getUserMedia + RTCPeerConnection bring-up.
  // The browser handles audio/video tracks directly via WebRTC SRTP;
  // the daemon brokers SDP exchange. Local media stays on this device
  // until the call ends - the daemon never sees the raw audio/video.
  // mediaState owns the media/route state; `media` is its read-only view.
  const mediaState = createCallMediaState();
  const media = mediaState.view;
  if (typeof window !== "undefined") {
    window._livingPresenceMedia = media;
  }

  function safeMediaPlay(el) {
    if (!el || typeof el.play !== "function") return;
    try {
      const p = el.play();
      if (p && typeof p.catch === "function") p.catch(() => {});
    } catch (_) {}
  }

  function buildMediaConstraints(base) {
    const wantAudio = !base || base.audio !== false;
    const wantVideo = !!(base && base.video);
    const audio = wantAudio
      ? (media.selectedAudioInputId
        ? {
            deviceId: { exact: media.selectedAudioInputId },
            noiseSuppression: media.voiceProcessing !== "raw",
            echoCancellation: media.voiceProcessing !== "raw",
            autoGainControl: media.voiceProcessing !== "raw",
          }
        : {
            noiseSuppression: media.voiceProcessing !== "raw",
            echoCancellation: media.voiceProcessing !== "raw",
            autoGainControl: media.voiceProcessing !== "raw",
          })
      : false;
    const video = wantVideo
      ? (media.selectedVideoInputId
        ? {
            deviceId: { exact: media.selectedVideoInputId },
            width: { ideal: 960, max: 1280 },
            height: { ideal: 540, max: 720 },
            frameRate: { ideal: 24, max: 30 },
          }
        : {
            width: { ideal: 960, max: 1280 },
            height: { ideal: 540, max: 720 },
            frameRate: { ideal: 24, max: 30 },
          })
      : false;
    return { audio, video };
  }

  async function requestRelayHealthProbe(reason) {
    if (!callUI.activeCallId || !media.iceRelayReady) return;
    const now = Date.now();
    if (now - Number(media.lastRelayProbeMs || 0) < 120000) return;
    mediaState.set("lastRelayProbeMs", now);
    try {
      const result = await fetch("/api/peer-rtc/relay-probe", {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          call_id: callUI.activeCallId,
          reason: reason || "call_health",
        }),
      }).then((r) => r.json());
      if (result && result.routePolicy) mediaState.recordRoutePolicy(result.routePolicy);
      reportCallEvent("relay_probe_completed", {
        reason: "relay_probe",
        state: media.bestRelayHealth || "unknown",
        ok: result && result.ok === true,
      });
    } catch (_) {
      reportCallEvent("relay_probe_failed", {
        reason: "relay_probe",
        state: media.bestRelayHealth || "unknown",
      });
    }
  }

  async function refreshIceConfigForCall(reason) {
    if (!callUI.activeCallId || !media.pc) return false;
    const now = Date.now();
    if (now - Number(media.lastIceConfigRefreshMs || 0) < 60000) return false;
    mediaState.set("lastIceConfigRefreshMs", now);
    try {
      const iceUrl = `/api/peer-rtc/ice-config?call_id=${encodeURIComponent(callUI.activeCallId)}`;
      const cfg = await fetch(iceUrl, {
        credentials: "include", cache: "no-store",
      }).then((r) => r.json());
      if (Array.isArray(cfg.iceServers) && cfg.iceServers.length > 0) {
        media.pc.setConfiguration({ iceServers: cfg.iceServers });
      }
      mediaState.set("localCandidateAddresses", _callLocalAddressesFromIceConfig(cfg));
      mediaState.set("iceRelayReady", Array.isArray(cfg.iceServers)
        && cfg.iceServers.some((srv) => {
          const urls = Array.isArray(srv.urls) ? srv.urls : [srv.urls];
          return urls.some((u) => String(u || "").toLowerCase().startsWith("turn:") || String(u || "").toLowerCase().startsWith("turns:"));
        }));
      mediaState.recordRoutePolicy(cfg.routePolicy);
      reportCallEvent("turn_credentials_refreshed", {
        reason: reason || "credential_refresh",
        state: media.iceRelayReady ? "relay" : "direct",
        ok: true,
      });
      return true;
    } catch (_) {
      reportCallEvent("turn_credentials_refresh_failed", {
        reason: reason || "credential_refresh",
        state: media.iceRelayReady ? "relay" : "direct",
      });
      return false;
    }
  }

  function maybeRefreshTurnCredentials(reason) {
    if (!media.turnCredentialExpiresAtMs || !media.iceRelayReady) return;
    const msLeft = Number(media.turnCredentialExpiresAtMs || 0) - Date.now();
    if (msLeft > 0 && msLeft < 120000) {
      refreshIceConfigForCall(reason || "credential_expiring").catch(() => {});
    }
  }

  function targetMediaProfile(level) {
    return [
      { name: "full", width: 1280, height: 720, frameRate: 30, maxBitrate: 1800000, scale: 1 },
      { name: "steady", width: 960, height: 540, frameRate: 24, maxBitrate: 850000, scale: 1.5 },
      { name: "survival", width: 640, height: 360, frameRate: 18, maxBitrate: 360000, scale: 2.5 },
      { name: "audio-first", width: 426, height: 240, frameRate: 12, maxBitrate: 160000, scale: 4 },
    ][Math.max(0, Math.min(3, Number(level || 0)))] || null;
  }

  async function applyCaptureProfileForTau(level, reason) {
    const profile = targetMediaProfile(level);
    if (!profile || callUI.lastCaptureProfile === profile.name) return;
    const track = media.localStream && media.localStream.getVideoTracks()[0];
    if (!track || typeof track.applyConstraints !== "function" || track.readyState !== "live") return;
    try {
      await track.applyConstraints({
        width: { ideal: profile.width, max: profile.width },
        height: { ideal: profile.height, max: profile.height },
        frameRate: { ideal: profile.frameRate, max: profile.frameRate },
      });
      callState.set("lastCaptureProfile", profile.name);
      reportCallEvent("tau_capture_adapted", {
        state: profile.name === "audio-first" ? "survival" : profile.name,
        reason: reason || "metrics",
      });
    } catch (_) {
      reportCallEvent("tau_capture_adapt_failed", { reason: reason || "metrics" });
    }
  }

  async function startLocalMedia(constraints) {
    // Doctrine §3.3.c: permissions are asked at install or first
    // call, never mid-call. If the user denied, fall through to
    // audio-only or text. Never throw.
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      return null;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia(
        buildMediaConstraints(constraints || { audio: true, video: true }),
      );
      mediaState.set("localStream", stream);
      attachLocalPreview(stream);
      refreshCallDevicePickers().catch(() => {});
      return stream;
    } catch (_) {
      // Permissions denied / no devices. Try audio-only fallback.
      if (constraints && constraints.video) {
        try {
          const audioOnly = await navigator.mediaDevices.getUserMedia(
            { audio: true },
          );
          mediaState.set("localStream", audioOnly);
          refreshCallDevicePickers().catch(() => {});
          // No video preview to show - but the call can still
          // proceed with voice.
          return audioOnly;
        } catch (_) { /* fall through to silent */ }
      }
      return null;
    }
  }

  function attachLocalPreview(stream) {
    const v = $$("#call-local-video");
    if (!v) return;
    v.srcObject = stream;
    // Only show the preview pip if we actually have video.
    const hasVideo = stream.getVideoTracks().length > 0;
    v.classList.toggle("show", hasVideo);
    safeMediaPlay(v);
  }

  function remoteVideoSurfaceState() {
    const stream = media.remoteStream;
    const v = $$("#call-remote-video");
    const a = $$("#call-remote-audio");
    const surface = $$("#call-active-surface");
    const videoTracks = stream ? stream.getVideoTracks() : [];
    const audioTracks = stream ? stream.getAudioTracks() : [];
    const liveVideoTracks = videoTracks.filter((t) => t.readyState === "live");
    const liveAudioTracks = audioTracks.filter((t) => t.readyState === "live");
    const unmutedLiveVideoTracks = liveVideoTracks.filter((t) => t.muted !== true);
    const hasRenderableVideo = unmutedLiveVideoTracks.length > 0
      && (
        Number(v?.videoWidth || 0) > 0
        || Number(v?.readyState || 0) >= 2
        || Number(callUI.lastMetricsSnapshot?.inbound_video_frames_decoded || 0) > 0
        || Number(callUI.lastMetricsSnapshot?.inbound_video_packets || 0) > 0
      );
    return {
      stream,
      videoEl: v,
      audioEl: a,
      surface,
      videoTracks,
      audioTracks,
      liveVideoTracks,
      liveAudioTracks,
      unmutedLiveVideoTracks,
      hasRenderableVideo,
      videoShown: v ? v.classList.contains("show") : false,
      surfaceShown: surface ? surface.classList.contains("has-remote-video") : false,
      srcVideoMatches: !!(v && stream && v.srcObject === stream),
      srcAudioMatches: !!(a && stream && a.srcObject === stream),
    };
  }

  function syncRemoteMediaSurface(reason) {
    const state = remoteVideoSurfaceState();
    if (state.stream) {
      if (state.videoEl && state.videoEl.srcObject !== state.stream) state.videoEl.srcObject = state.stream;
      if (state.audioEl && state.audioEl.srcObject !== state.stream) state.audioEl.srcObject = state.stream;
    }
    if (state.videoEl) {
      state.videoEl.classList.toggle("show", state.hasRenderableVideo);
      if (state.stream && state.liveVideoTracks.length) safeMediaPlay(state.videoEl);
    }
    if (state.audioEl) {
      if (state.stream && state.liveAudioTracks.length) {
        applyAudioOutputDevice(state.audioEl).catch(() => {});
        safeMediaPlay(state.audioEl);
      }
    }
    if (state.surface) state.surface.classList.toggle("has-remote-video", state.hasRenderableVideo);
    const changed = state.videoShown !== state.hasRenderableVideo
      || state.surfaceShown !== state.hasRenderableVideo
      || (state.stream && (!state.srcVideoMatches || !state.srcAudioMatches));
    const now = Date.now();
    if (changed || now - Number(callUI.lastRemoteSurfaceSyncMs || 0) > 7000) {
      callState.set("lastRemoteSurfaceSyncMs", now);
      reportCallEvent("remote_surface_synced", {
        reason: reason || "sync",
        remote_video_visible: state.hasRenderableVideo,
        remote_video_tracks: state.videoTracks.length,
        remote_live_video_tracks: state.liveVideoTracks.length,
        remote_unmuted_video_tracks: state.unmutedLiveVideoTracks.length,
        remote_audio_tracks: state.audioTracks.length,
        remote_live_audio_tracks: state.liveAudioTracks.length,
      });
    }
    return state;
  }

  function attachRemoteStream(stream) {
    mediaState.set("remoteStream", stream);
    syncRemoteMediaSurface("attach_remote_stream");
  }

  function remoteTrackSummary() {
    const stream = media.remoteStream;
    if (!stream) return [];
    return stream.getTracks().map((track) => ({
      kind: track.kind || "",
      readyState: track.readyState || "",
      muted: track.muted === true,
      enabled: track.enabled !== false,
    }));
  }

  function bindRemoteTrackDiagnostics(track) {
    if (!track || track._oneLinkTraceBound) return;
    track._oneLinkTraceBound = true;
    track.onmute = () => {
      addOneCallEvent(`Remote ${track.kind} paused.`);
      reportCallEvent("remote_track_muted", { media_kind: track.kind });
      syncRemoteMediaSurface(`remote_${track.kind}_muted`);
      reportCallMetricsOnce();
    };
    track.onunmute = () => {
      addOneCallEvent(`Remote ${track.kind} flowing.`);
      reportCallEvent("remote_track_unmuted", { media_kind: track.kind });
      syncRemoteMediaSurface(`remote_${track.kind}_unmuted`);
      reportCallMetricsOnce();
    };
    track.onended = () => {
      addOneCallEvent(`Remote ${track.kind} ended.`);
      reportCallEvent("remote_track_ended", { media_kind: track.kind });
      syncRemoteMediaSurface(`remote_${track.kind}_ended`);
      reportCallMetricsOnce();
      repairMediaPath(`remote_${track.kind}_ended`).catch(() => {});
    };
  }

