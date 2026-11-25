  // ── Public entry: a contact "Call" button calls this. ──
  window.startLivingPresenceCall = async function (
    peerMasterVkHex, peerLabel, opts,
  ) {
    // May 15 2026 - `opts` is an optional `{ video: boolean }`.
    //   { video: true }  → voice + video call (camera on)
    //   { video: false } → voice-only call (camera off)
    // Default (no opts) preserves the legacy video-on behaviour so
    // older callers don't break.
    const wantVideo = !opts || opts.video !== false;
    const label = peerLabel || peerMasterVkHex.slice(0, 8);
    // v0.21.x: permission preflight. Before triggering the cold
    // browser getUserMedia prompt, run a one-time explainer modal
    // so the user knows WHY the browser is about to ask for mic /
    // camera. Skip when permissions are already granted (returning
    // user) OR when the user has acked the preflight before. On
    // Cancel: abort silently without firing the call_invite.
    const preflight = (
      typeof window._callPermissionPreflight === "function"
        ? window._callPermissionPreflight
        : async () => true
    );
    const proceed = await preflight({ video: wantVideo, peerLabel: label });
    if (!proceed) return;
    callUI.activeCallId = null;
    callUI.activeCallPeer = label;
    callUI.activeCallPeerFp = peerMasterVkHex;
    callUI.activeCallLocalRole = "originator";
    callUI.activeCallKind = wantVideo ? "video" : "voice";
    media.expectRemoteAudio = true;
    media.expectRemoteVideo = wantVideo;
    showOutgoingOverlay(label, {
      kind: wantVideo ? "video" : "voice",
    });
    addOneCallEvent("Starting secure call path...");
    setupRtcPeerConnection();
    callUI.localMediaReady = false;
    const mediaPromise = startLocalMedia({ audio: true, video: wantVideo });
    const result = await callApiPost({
      action: "initiate",
      peer_master_vk_hex: peerMasterVkHex,
      peer_label: label,
      kind: wantVideo ? "video" : "voice",
    });
    if (!result.ok) {
      if (typeof toast === "function") toast(result.user_message, "warn");
      hideOutgoingOverlay();
      stopAllMedia();
      callUI.activeCallId = null;
      callUI.activeCallPeer = null;
      callUI.activeCallPeerFp = null;
      callUI.activeCallLocalRole = "";
      return;
    }
    callUI.activeCallId = result.call_id;
    // v0.21.x: track this outgoing call so we get a missed-call /
    // ended-call bubble in chat when the daemon's phase_changed
    // event fires for ended/async_capture.
    _trackCallStart(result.call_id, {
      peerLabel: label,
      peerFp: peerMasterVkHex,
      direction: "out",
      kind: wantVideo ? "video" : "voice",
    });
    // Tier α: pre-warm local media so the mic (and optionally the
    // camera) are ready by the time the peer accepts. If
    // permissions are denied, the call still proceeds (text/voice-
    // note fallback). For a voice-only call we skip camera capture
    // entirely so the indicator light doesn't come on.
    const stream = await mediaPromise;
    if (stream && media.pc) {
      await ensureLocalTracksOnPeerConnectionSettled();
      // Tier β - attest the microphone stream for both voice and video.
      // The same bounded audio recorder also provides the short in-memory
      // buffer used if the call later converts into a capsule.
      startAttestStream(stream);
      // Wire the self-preview tile (video only). Lets the caller
      // see exactly what the peer will see when they pick up -
      // catches "wrong camera selected" / "lens cover on" before
      // they answer.
      if (wantVideo) {
        const selfPrev = $$("#call-outgoing-selfpreview");
        if (selfPrev) {
          try { selfPrev.srcObject = stream; } catch (_) {}
        }
      }
      // Apply any pre-call mute / pre-call camera-off the user
      // already chose on the overlay (handlers above only flip
      // the flag; the stream may not have existed yet).
      if (_outgoingState.preMuted) {
        stream.getAudioTracks().forEach((t) => { t.enabled = false; });
      }
      if (_outgoingState.preCamOff) {
        stream.getVideoTracks().forEach((t) => { t.enabled = false; });
      }
    }
    callUI.localMediaReady = true;
    reportCallEvent("local_media_ready", { reason: "start" });
    // Originator creates the SDP offer + sends it now. The peer
    // will respond with an SDP answer once they accept.
    await sendLocalSdpOffer();
  };

  /**
   * Compute peer initials for the avatar circle.
   * "Computer 2" -> "C2"; "Alice" -> "A"; "fc9f0a5f" -> "fc"
   */
