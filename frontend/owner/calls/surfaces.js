  function _peerInitials(label) {
    if (!label) return "?";
    const parts = String(label).trim().split(/\s+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    }
    return label.length >= 2
      ? (label[0] + label[1]).toUpperCase()
      : label[0].toUpperCase();
  }

  /**
   * Format elapsed seconds as M:SS for the ringing timer.
   */
  function _fmtElapsed(secs) {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s < 10 ? "0" : ""}${s}`;
  }

  // State for the outgoing overlay's per-call timers + handlers.
  const _outgoingState = {
    startedMs: 0,
    timerId: null,
    fallbackTimerId: null,
    preMuted: false,
    preCamOff: false,
  };

  function _resetOutgoingState() {
    if (_outgoingState.timerId) {
      clearInterval(_outgoingState.timerId);
      _outgoingState.timerId = null;
    }
    if (_outgoingState.fallbackTimerId) {
      clearTimeout(_outgoingState.fallbackTimerId);
      _outgoingState.fallbackTimerId = null;
    }
    if (_outgoingState.routeTimerId) {
      clearInterval(_outgoingState.routeTimerId);
      _outgoingState.routeTimerId = null;
    }
    _outgoingState.preMuted = false;
    _outgoingState.preCamOff = false;
    const elapsed = $$("#call-outgoing-elapsed");
    if (elapsed) elapsed.textContent = "";
    const fallback = $$("#call-outgoing-fallback");
    if (fallback) fallback.classList.remove("show");
    const preMute = $$("#btn-call-precmute");
    if (preMute) preMute.setAttribute("aria-pressed", "false");
    const preCam = $$("#btn-call-precam");
    if (preCam) preCam.setAttribute("aria-pressed", "false");
    const route = $$("#call-outgoing-route");
    if (route) route.textContent = "connecting…";
  }

  function showOutgoingOverlay(peerLabel, opts) {
    // opts: { kind: "voice"|"video" }
    const isVideo = !opts || opts.kind !== "voice";
    const overlay = $$("#call-outgoing-overlay");
    const peer = $$("#call-outgoing-peer");
    const avatar = $$("#call-outgoing-avatar");
    const kindBadge = $$("#call-outgoing-kind");
    const kindIcon = $$("#call-outgoing-kind-icon");
    const kindText = $$("#call-outgoing-kind-text");
    const preCamBtn = $$("#btn-call-precam");

    if (peer) peer.textContent = peerLabel;
    if (avatar) avatar.textContent = _peerInitials(peerLabel);
    if (kindBadge) kindBadge.setAttribute("data-kind", isVideo ? "video" : "voice");
    if (kindIcon) kindIcon.textContent = isVideo ? "📹" : "📞";
    if (kindText) kindText.textContent = isVideo ? "Video call" : "Voice call";
    // Hide the pre-camera toggle for voice-only calls.
    if (preCamBtn) preCamBtn.style.display = isVideo ? "" : "none";

    _resetOutgoingState();
    if (overlay) {
      overlay.classList.add("show");
      overlay.classList.toggle("has-video", isVideo);
    }
    // v0.21.x: audible ringback while waiting for peer to pick up.
    // Honors quiet hours, peer mute, and notification-sound toggle.
    if (typeof window.startCallRingback === "function") {
      window.startCallRingback({ peer_fp: callUI.activeCallPeerFp });
    }

    // Kick off the elapsed-seconds counter (ticks every 1s).
    _outgoingState.startedMs = Date.now();
    const tick = () => {
      const secs = Math.floor((Date.now() - _outgoingState.startedMs) / 1000);
      const elapsed = $$("#call-outgoing-elapsed");
      if (elapsed) elapsed.textContent = _fmtElapsed(secs);
    };
    tick();
    _outgoingState.timerId = setInterval(tick, 1000);

    // After 8 seconds with no answer, surface the "send a message
    // instead" fallback so the user can downgrade gracefully.
    _outgoingState.fallbackTimerId = setTimeout(() => {
      const fallback = $$("#call-outgoing-fallback");
      if (fallback) fallback.classList.add("show");
    }, 8000);

    // Probe the daemon's connection-status endpoint to label the
    // route. Refresh every 2.5s while the overlay is up - the
    // detected regime may sharpen as the dial progresses.
    _refreshOutgoingRoute().catch(() => { /* non-fatal */ });
    _outgoingState.routeTimerId = setInterval(() => {
      _refreshOutgoingRoute().catch(() => {});
    }, 2500);
  }

  /**
   * Best-effort: pull per-peer regime + latency from /api/peers
   * (the same data the sidebar surfaces) and write a one-liner
   * route label under the status. Silent on failure - the call
   * surface must never block on a network probe.
   */
  async function _refreshOutgoingRoute() {
    try {
      const peerFp = callUI.activeCallPeerFp;
      if (!peerFp) return;
      const r = await fetch("/api/peers", {
        headers: { Accept: "application/json" },
        credentials: "same-origin",
      });
      if (!r.ok) return;
      const body = await r.json();
      const peer = (body.peers || []).find(
        (p) => p.fingerprint === peerFp || p.short_id === peerFp,
      );
      const route = $$("#call-outgoing-route");
      if (!route) return;
      if (!peer) {
        route.textContent = "no route";
        return;
      }
      // WHO DECIDES what this connection is called.
      //
      // `peer.certified_link` comes from a renderer whose claims are DISCHARGED over every
      // integer input (idem/scripts/emit_certified_views.py):
      //
      //   never-claims-DIRECT-for-a-link-that-is-not
      //   never-claims-SECURE-for-an-unauthenticated-link
      //   offline-never-renders-as-connected
      //   an-unauthenticated-live-link-always-warns
      //
      // That matters here more than for the identity badge: "direct" and "secure" describe
      // infrastructure the user cannot inspect, so this string is the only thing standing
      // between them and believing a relayed conversation is peer-to-peer.
      //
      // The fallback below is the old string table. Note its last line was `return r;` --
      // an unrecognised regime printed straight through as a raw protocol token, which is
      // both meaningless to a user and an unbounded claim. The proven path has no such
      // branch: an unknown regime renders as RELAYED, because the law leaves nowhere to
      // put "and otherwise".
      const certified = peer.certified_link;
      const proven = certified && typeof certified.spoken === "string";
      const regimeLabel = (() => {
        if (proven) return certified.spoken;
        const r = peer.regime;
        if (!r) return peer.online ? "connecting…" : "offline";
        if (r === "relay") return "via relay";
        if (r === "lan") return "local network";
        if (r === "internet") return "internet";
        if (r === "offline") return "offline";
        // An unrecognised regime is NOT printed raw. The old code ended `return r;`, putting a
        // protocol token on screen -- meaningless to a user, and an unbounded claim about a
        // connection nobody has classified. "unknown route" says exactly what is known.
        return "unknown route";
      })();
      const latency = peer.latency_ms != null
        ? ` - ${Math.round(peer.latency_ms)} ms`
        : "";
      // A link that cannot be authenticated must SAY so, and the proof decides when.
      const warnMark = (proven && certified.warn) ? " ⚠" : "";
      route.textContent = `${regimeLabel}${latency}${warnMark}`;
      route.setAttribute("data-proven", proven ? "yes" : "unavailable");
      if (proven) route.setAttribute("data-claims-direct", String(!!certified.claims_direct));
    } catch (_) { /* silent - never block the call surface */ }
  }

  function hideOutgoingOverlay() {
    const overlay = $$("#call-outgoing-overlay");
    if (overlay) overlay.classList.remove("show");
    // v0.21.x: cut ringback the instant the overlay closes (accept,
    // decline, hangup, fallback to message). Idempotent.
    if (typeof window.stopCallRing === "function") window.stopCallRing();
    _resetOutgoingState();
    // Detach the self-preview video. It points at the same MediaStream
    // that is already attached to RTCPeerConnection, so stopping tracks
    // here would kill mic/camera exactly when the call becomes active.
    const selfPrev = $$("#call-outgoing-selfpreview");
    if (selfPrev) {
      try {
        if (selfPrev.srcObject && selfPrev.srcObject !== media.localStream) {
          selfPrev.srcObject.getTracks().forEach((t) => {
            try { t.stop(); } catch (_) {}
          });
        }
        selfPrev.srcObject = null;
      } catch (_) {}
    }
  }

  // Pre-call control handlers via event delegation. Toggle local-
  // media tracks before the peer picks up. The state propagates to
  // startLocalMedia / setupRtcPeerConnection so the call lands in
  // the chosen state. Delegated so the wire-up doesn't depend on
  // DOM-ready timing or element existence at script time.
  document.addEventListener("click", (ev) => {
    const t = ev.target;
    if (!t || !(t instanceof Element)) return;
    const preMute = t.closest("#btn-call-precmute");
    if (preMute) {
      _outgoingState.preMuted = !_outgoingState.preMuted;
      preMute.setAttribute("aria-pressed",
        _outgoingState.preMuted ? "true" : "false");
      preMute.title = _outgoingState.preMuted
        ? "Microphone muted. They won't hear you on pickup."
        : "Mute before they pick up";
      if (media && media.localStream) {
        media.localStream.getAudioTracks().forEach((tr) => {
          tr.enabled = !_outgoingState.preMuted;
        });
      }
      return;
    }
    const preCam = t.closest("#btn-call-precam");
    if (preCam) {
      _outgoingState.preCamOff = !_outgoingState.preCamOff;
      preCam.setAttribute("aria-pressed",
        _outgoingState.preCamOff ? "true" : "false");
      preCam.title = _outgoingState.preCamOff
        ? "Camera off. They'll see your avatar on pickup."
        : "Turn camera off before they pick up";
      if (media && media.localStream) {
        media.localStream.getVideoTracks().forEach((tr) => {
          tr.enabled = !_outgoingState.preCamOff;
        });
      }
      return;
    }
    const sendMsg = t.closest("#btn-call-send-msg-instead");
    if (sendMsg) {
      (async () => {
        const peerFp = callUI.activeCallPeerFp;
        try {
          if (callUI.activeCallId) {
            await callApiPost({
              action: "cancel",
              call_id: callUI.activeCallId,
              reason: "downgraded_to_message",
            });
          }
        } catch (_) {}
        hideOutgoingOverlay();
        if (peerFp && typeof selectPeer === "function") {
          selectPeer(peerFp);
          const composer = $$("#msg-input");
          if (composer) composer.focus();
        }
      })();
      return;
    }
  });
  function showIncomingRing(peerLabel) {
    const peer = $$("#call-incoming-peer");
    if (peer) peer.textContent = peerLabel;
    const avatar = $$("#call-incoming-avatar");
    if (avatar) avatar.textContent = _peerInitials(peerLabel || "One");
    const overlay = $$("#call-incoming-overlay");
    if (overlay) overlay.classList.add("show");
    // v0.21.x: audible phone-style ringtone. Plays even when the
    // tab is unfocused (Web Audio doesn't pause on blur). Honors
    // peer mute via callUI.activeCallPeerFp when set, otherwise
    // plays for any incoming call.
    if (typeof window.startCallRingtone === "function") {
      window.startCallRingtone({ peer_fp: callUI?.activeCallPeerFp });
    }
    try {
      if (
        "Notification" in window &&
        Notification.permission === "granted" &&
        navigator.serviceWorker?.controller
      ) {
        navigator.serviceWorker.controller.postMessage({
          type: "incoming-call-notification",
          title: `${peerLabel || "One Link"} is calling`,
          body: "Accept or open the chat.",
          call_id: callUI.inboundCallId || "",
          peer: callUI.inboundCallPeerFp || "",
        });
      }
    } catch (_) {}
  }
  function hideIncomingRing() {
    const overlay = $$("#call-incoming-overlay");
    if (overlay) overlay.classList.remove("show");
    // v0.21.x: cut the ringtone on any dismissal path (accept,
    // decline, end, peer hangup before pickup). Idempotent.
    if (typeof window.stopCallRing === "function") window.stopCallRing();
  }
  function showActiveSurface(peerLabel, rungLabel) {
    const name = $$("#call-active-name");
    const rung = $$("#call-active-rung");
    const face = $$("#call-active-face");
    if (name) name.textContent = peerLabel;
    if (rung) rung.textContent = rungLabel || "Connected privately over One Link";
    if (face) face.textContent = _peerInitials(peerLabel || "One");
    const surface = $$("#call-active-surface");
    if (surface) surface.classList.add("show");
    if (surface) surface.classList.remove("details-open");
    // v0.21.x: defensive — cut any lingering ringback/ringtone the
    // moment the call connects. The overlay-hide paths usually
    // handle this already, but if a peer accepts the same instant
    // the timer would fire a next pulse, this ensures silence
    // before the active call audio takes over.
    if (typeof window.stopCallRing === "function") window.stopCallRing();
    resetOneCallRail(peerLabel);
    renderCallHistory();
    renderParticipants();
    renderLiveStats(callUI.lastMetricsSnapshot || {});
    startCallTelemetry();
  }
  function hideActiveSurface() {
    const surface = $$("#call-active-surface");
    // doctrine-ok: §3.2.a internal state class removal; no user-facing reconnect prompt.
    if (surface) surface.classList.remove("show", "details-open", "reconnecting");
    const badge = $$("#call-recording-badge");
    if (badge) badge.classList.remove("show");
    stopCallTelemetry();
    setReconnectState(false);
  }
  function showRecordingBadge() {
    const badge = $$("#call-recording-badge");
    if (badge) badge.classList.add("show");
  }
  function hideRecordingBadge() {
    const badge = $$("#call-recording-badge");
    if (badge) badge.classList.remove("show");
  }

  function peerLabelFromCall(call) {
    return (
      (call && (call.peer_label || call.peer_display_name)) ||
      (call && call.peer_master_vk_hex && call.peer_master_vk_hex.slice(0, 8)) ||
      (call && call.call_id && call.call_id.slice(0, 8)) ||
      "That device"
    );
  }

  function updateOneChip(id, value) {
    const el = $$(id);
    if (el) el.textContent = value;
  }

  function isNoisyCallEvent(text) {
    return /^(Preparing media|Media offer|Media answer|Resending media|Repairing media|Media route|Remote .* paused|Remote .* flowing)/i
      .test(String(text || ""));
  }

  function addOneCallEvent(text) {
    if (!text) return;
    if (isNoisyCallEvent(text)) return;
    callState.recordOneEvent({ text, at: Date.now() });
    const feed = $$("#call-one-feed");
    if (!feed) return;
    feed.innerHTML = callUI.oneEvents.map((ev) => (
      `<div class="call-one-event">${escapeText(ev.text)}</div>`
    )).join("");
  }

  function reportCallEvent(event, extra) {
    const callId = callUI.activeCallId || callUI.inboundCallId;
    if (!callId || !event) return;
    callApiPost({
      action: "report_call_event",
      call_id: callId,
      event,
      ...(extra || {}),
    }).catch(() => {});
  }

  function showCallFileStatus(text, kind) {
    const box = $$("#call-one-file-status");
    if (!box) return;
    box.textContent = text || "";
    box.classList.toggle("show", !!text);
    box.style.borderColor = kind === "bad"
      ? "rgba(239,68,68,0.35)"
      : "rgba(34,197,94,0.24)";
    box.style.background = kind === "bad"
      ? "rgba(239,68,68,0.12)"
      : "rgba(34,197,94,0.12)";
  }

  function resetOneCallRail(peerLabel) {
    callState.clearOneEvents();
    updateOneChip("#call-one-score", "Protected");
    updateOneChip("#call-one-route", "Local");
    updateOneChip("#call-one-rtt", "--");
    updateOneChip("#call-one-loss", "0%");
    updateOneChip("#call-one-reality", "Checking");
    updateOneChip("#call-one-privacy", "Private");
    updateOneChip("#call-one-engine", "Auto");
    showCallFileStatus("", "");
    addOneCallEvent(`${peerLabel || "This call"} is protected by One Link.`);
    addOneCallEvent("Files, voice, video, and routing share the same trusted path.");
  }

