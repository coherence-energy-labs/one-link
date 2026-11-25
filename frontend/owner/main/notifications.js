  let _audioCtx = null;
  function _getAudioCtx() {
    if (!_audioCtx) {
      try {
        _audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      } catch { return null; }
    }
    if (_audioCtx.state === "suspended") _audioCtx.resume().catch(() => {});
    return _audioCtx;
  }
  function playNotificationChime() {
    if (!state.runtimeSettings?.notification_sound) return;
    const ctx = _getAudioCtx();
    if (!ctx) return;
    const now = ctx.currentTime;
    // Two notes: G5 (784 Hz) → C6 (1047 Hz). Quick, pleasant.
    [
      { freq: 784, start: 0,    dur: 0.12 },
      { freq: 1047, start: 0.10, dur: 0.16 },
    ].forEach(({ freq, start, dur }) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.0001, now + start);
      gain.gain.exponentialRampToValueAtTime(0.18, now + start + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + start + dur);
      osc.connect(gain).connect(ctx.destination);
      osc.start(now + start);
      osc.stop(now + start + dur + 0.05);
    });
  }
  // v0.21.x: synthesized ring audio for calls. Two flavors:
  //   - Ringback (outgoing): quiet sine pulse, 0.5s on / 0.5s off,
  //     reassures the caller that something is happening. Stopped
  //     on accept / decline / end.
  //   - Ringtone (incoming): louder dual-frequency phone-style ring,
  //     1s on / 0.4s gap, repeating. Stopped on accept / decline /
  //     end. Honors notification-sound + quiet-hours + peer-mute
  //     just like other in-app audio.
  // Synthesizing in-browser avoids shipping audio assets and lets
  // the user mute by toggling notification sound.
  const _callRingState = {
    timer: null,
    nodes: [],
  };
  function _stopCallRing() {
    if (_callRingState.timer) {
      clearInterval(_callRingState.timer);
      _callRingState.timer = null;
    }
    for (const n of _callRingState.nodes) {
      try { n.stop(); } catch (_) {}
      try { n.disconnect(); } catch (_) {}
    }
    _callRingState.nodes = [];
  }
  function _scheduleRingPulse({ freqs, dur, gainPeak, when }) {
    const ctx = _getAudioCtx();
    if (!ctx) return;
    const start = when ?? ctx.currentTime;
    for (const f of freqs) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.value = f;
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(gainPeak, start + 0.02);
      gain.gain.setValueAtTime(gainPeak, start + dur - 0.04);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + dur);
      osc.connect(gain).connect(ctx.destination);
      osc.start(start);
      osc.stop(start + dur + 0.05);
      _callRingState.nodes.push(osc, gain);
    }
  }
  function _shouldPlayCallRing(opts = {}) {
    if (state.runtimeSettings?.notification_sound === false) return false;
    if (isQuietHoursActive()) return false;
    if (opts.peer_fp) {
      const peer = [...state.peers.values()]
        .find((p) => p.fingerprint === opts.peer_fp);
      if (peer?.muted) return false;
    }
    return true;
  }
  function startCallRingback(opts = {}) {
    _stopCallRing();
    if (!_shouldPlayCallRing(opts)) return;
    // Quiet single-tone pulse, classic "I'm calling, they're ringing" feel.
    // 0.5s on, 0.5s silence, repeating.
    const pulse = () => {
      _scheduleRingPulse({ freqs: [440], dur: 0.45, gainPeak: 0.04 });
    };
    pulse();
    _callRingState.timer = setInterval(pulse, 1000);
  }
  function startCallRingtone(opts = {}) {
    _stopCallRing();
    if (!_shouldPlayCallRing(opts)) return;
    // Dual-frequency phone-style ring, louder than ringback. Two
    // short pulses (1s + 1s) followed by a 1.2s gap = recognizable
    // ring cadence.
    const ctx = _getAudioCtx();
    if (!ctx) return;
    const ring = () => {
      const t0 = ctx.currentTime;
      _scheduleRingPulse({ freqs: [440, 480], dur: 0.4, gainPeak: 0.10, when: t0 });
      _scheduleRingPulse({ freqs: [440, 480], dur: 0.4, gainPeak: 0.10, when: t0 + 0.6 });
    };
    ring();
    // Total cadence 2.4s (0.4 + 0.2 + 0.4 + 1.4 gap)
    _callRingState.timer = setInterval(ring, 2400);
  }
  function stopCallRing() {
    _stopCallRing();
  }
  if (typeof window !== "undefined") {
    window.startCallRingback = startCallRingback;
    window.startCallRingtone = startCallRingtone;
    window.stopCallRing = stopCallRing;
  }

  function soundOnIncoming(opts = {}) {
    if (isQuietHoursActive()) return;
    if (opts.peer_fp) {
      const peer = [...state.peers.values()]
        .find(p => p.fingerprint === opts.peer_fp);
      if (peer?.muted) return;
    }
    playNotificationChime();
  }

  // v0.21.x: increment / decrement / refresh unread surfaces.
  //
  // Single source of truth: state.unreadByPeer + state.totalUnread.
  // Document title prefix and navigator.setAppBadge() (the OS-level
  // dock / taskbar count) are derived. Browser tab title format:
  // "(N) One Link" mirrors iMessage/Slack/Discord.
  const _BASE_TAB_TITLE = "One Link";
  function _refreshUnreadSurfaces() {
    const total = state.totalUnread || 0;
    try {
      document.title = total > 0
        ? `(${total > 99 ? "99+" : total}) ${_BASE_TAB_TITLE}`
        : _BASE_TAB_TITLE;
    } catch {}
    try {
      if (total > 0 && navigator.setAppBadge) {
        navigator.setAppBadge(total).catch(() => {});
      } else if (navigator.clearAppBadge) {
        navigator.clearAppBadge().catch(() => {});
      }
    } catch {}
  }
  function bumpUnread(peerShortId) {
    if (!peerShortId) return;
    state.unreadByPeer[peerShortId] = (state.unreadByPeer[peerShortId] || 0) + 1;
    state.totalUnread = (state.totalUnread || 0) + 1;
    _refreshUnreadSurfaces();
    try { renderPeers(); } catch {}
  }
  function clearUnread(peerShortId) {
    if (!peerShortId) return;
    const prev = state.unreadByPeer[peerShortId] || 0;
    if (prev === 0) return;
    delete state.unreadByPeer[peerShortId];
    state.totalUnread = Math.max(0, (state.totalUnread || 0) - prev);
    _refreshUnreadSurfaces();
    try { renderPeers(); } catch {}
    if (state.selectedPeer === peerShortId) {
      try { scheduleRenderMessages(); } catch {}
    }
  }
  function clearAllUnread() {
    if (!state.totalUnread) return;
    state.unreadByPeer = {};
    state.totalUnread = 0;
    _refreshUnreadSurfaces();
  }
  // On window focus, clear unread for the currently-selected peer
  // (the user IS reading those messages right now). Other peers
  // keep their badges until they're opened.
  window.addEventListener("focus", () => {
    if (state.selectedPeer) clearUnread(state.selectedPeer);
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.selectedPeer) clearUnread(state.selectedPeer);
  });

  function notifyIncoming(title, body, opts = {}) {
    // v0.10.0: pair the desktop notification with the chime.
    soundOnIncoming(opts);
    if (!notifySupported()) return;
    if (Notification.permission !== "granted") return;
    if (document.hasFocus()) return;
    // v0.10.0: do-not-disturb suppresses BOTH the chime AND the
    // desktop notification. Messages still arrive - they just
    // don't ping.
    if (isQuietHoursActive()) return;
    // v0.7.3: respect per-device mute. Caller passes peer_fp; if
    // that peer's record is `muted`, swallow the notification.
    if (opts.peer_fp) {
      const peer = [...state.peers.values()]
        .find(p => p.fingerprint === opts.peer_fp);
      if (peer?.muted) return;
    }
    try {
      const n = new Notification(title, {
        body: body || "",
        icon: "/static/one-glyph.png",
        silent: false,
      });
      n.onclick = () => { window.focus(); n.close(); };
      setTimeout(() => { try { n.close(); } catch {} }, 8000);
    } catch {}
  }

  // ── v0.10.4 presence ──────────────────────────────────────────────
  // User's own status: 'online' (default) | 'away' | 'dnd' |
  // 'invisible'. Set via the pill dropdown; persisted via
  // /api/presence; broadcast to peers as a PRESENCE wire frame.
  state.myPresence = "online";

  function applyPresenceUI(status) {
    const dot = $("#presence-dot");
    if (dot) {
      dot.className = "dot " + (status || "online");
    }
    state.myPresence = status || "online";
    document.querySelectorAll("#presence-menu [data-presence]").forEach((b) => {
      b.classList.toggle("active", b.dataset.presence === state.myPresence);
    });
  }

  async function setMyPresence(status) {
    try {
      const r = await api.post("/api/presence", { status });
      applyPresenceUI(r.presence);
      const labels = {
        online: "Online", away: "Away",
        dnd: "Do not disturb", invisible: "Appearing offline",
      };
      toast(labels[r.presence] || r.presence, "good", 2000);
    } catch (e) {
      toast(`Status update failed: ${errorToastBody(e)}`, "bad");
    }
  }

  // Pill click → toggle menu.
  $("#presence-pill")?.addEventListener("click", (e) => {
    e.stopPropagation();
    const menu = $("#presence-menu");
    if (!menu) return;
    menu.style.display = menu.style.display === "block" ? "none" : "block";
  });
  document.addEventListener("click", (e) => {
    const menu = $("#presence-menu");
    if (!menu) return;
    if (!menu.contains(e.target) && e.target.id !== "presence-pill"
        && !$("#presence-pill")?.contains(e.target)) {
      menu.style.display = "none";
    }
  });
  document.querySelectorAll("#presence-menu [data-presence]").forEach((b) => {
    b.addEventListener("click", () => {
      $("#presence-menu").style.display = "none";
      setMyPresence(b.dataset.presence);
    });
  });

