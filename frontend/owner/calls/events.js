  // ── WebSocket call_event router ──
  // The daemon broadcasts call_event tail events; we listen for the
  // call_event type on the existing WebSocket. The handler in
  // index.html's main ws.onmessage forwards them here.
  const callFileInput = $$("#call-file-input");
  const callSendFileBtn = $$("#btn-call-send-file");
  let _callFileSendInFlight = false;
  let _callFileRetryIntents = [];
  async function _sendCallFileIntents(intents) {
    if (_callFileSendInFlight || !intents.length) return;
    _callFileSendInFlight = true;
    if (callSendFileBtn) callSendFileBtn.disabled = true;
    const failed = [];
    try {
      for (const intent of intents) {
        const {file, peerId, clientDeliveryId} = intent;
        showCallFileStatus(`Sending ${file.name} through this call's trusted path...`, "info");
        addOneCallEvent(`Sending ${file.name} without leaving the call.`);
        try {
          const result = await api.upload(peerId, file, {clientDeliveryId});
          if (result && (result.background || result.queued || result.paused)) {
            showCallFileStatus(`${file.name} is securely staged and will finish automatically.`, "info");
            addOneCallEvent(`${file.name} will finish when the best path is ready.`);
          } else {
            showCallFileStatus(`${file.name} sent through One Link.`, "ok");
            addOneCallEvent(`${file.name} sent on the trusted file fabric.`);
          }
        } catch (e) {
          failed.push(intent);
          showCallFileStatus(
            `${file.name}: ${errorToastBody(e)}. Press Send file to retry this exact intent.`,
            "bad",
          );
        }
      }
      _callFileRetryIntents = failed;
    } finally {
      _callFileSendInFlight = false;
      if (callSendFileBtn) callSendFileBtn.disabled = false;
    }
  }
  if (callSendFileBtn) callSendFileBtn.addEventListener("click", () => {
    if (!callUI.activeCallId || !callUI.activeCallPeerFp) {
      showCallFileStatus("Pick an active One Link call first.", "bad");
      return;
    }
    if (_callFileSendInFlight) {
      showCallFileStatus("That file intent is already being sent.", "info");
      return;
    }
    const retries = _callFileRetryIntents.filter(
      (intent) => intent.peerId === callUI.activeCallPeerFp
    );
    if (retries.length) {
      void _sendCallFileIntents(retries);
      return;
    }
    if (callFileInput) callFileInput.click();
  });
  if (callFileInput) callFileInput.addEventListener("change", async (ev) => {
    const files = Array.from(ev.target.files || []);
    ev.target.value = "";
    const peerId = callUI.activeCallPeerFp;
    if (!files.length || !peerId) return;
    if (_callFileSendInFlight) {
      showCallFileStatus("A file intent is already being sent.", "info");
      return;
    }
    // Capture the complete batch before the first await. Retries retain these
    // exact File objects, targets, and delivery keys.
    const intents = files.map((file) => ({
      file,
      peerId,
      clientDeliveryId: _newClientMsgId(),
    }));
    await _sendCallFileIntents(intents);
  });

  const bestPathBtn = $$("#btn-call-use-best-path");
  if (bestPathBtn) bestPathBtn.addEventListener("click", () => {
    reportCallMetricsOnce();
    updateOneChip("#call-one-engine", "Scanning");
    updateOneChip("#call-one-route", "Best path");
    addOneCallEvent("One Link is checking local, trusted, and backup paths for this call.");
  });

  // v0.21.x: per-call lifecycle tracking so we can synthesize a
  // "missed call" bubble for calls that ended without reaching
  // active phase (peer_declined, invite_timeout, originator
  // cancelled). In-memory; the daemon-side persistence ship will
  // replace this with durable history.
  if (!callUI._callTracking) callUI._callTracking = {};
  function _trackCallStart(callId, info) {
    if (!callId) return;
    callUI._callTracking[callId] = {
      peerLabel: info.peerLabel || "",
      peerFp: info.peerFp || null,
      direction: info.direction || "out",
      kind: info.kind || "voice",
      startedMs: Date.now(),
      reachedActive: false,
      endedAt: null,
    };
  }
  function _markCallActive(callId) {
    const t = callUI._callTracking[callId];
    if (t) t.reachedActive = true;
  }
  function _resolveCallEnded(callId, endCause) {
    const t = callUI._callTracking[callId];
    if (!t || t.endedAt) return;
    t.endedAt = Date.now();
    if (!t.reachedActive) {
      _renderMissedCallBubble(callId, t, endCause);
    } else {
      _renderEndedCallBubble(callId, t, endCause);
    }
    delete callUI._callTracking[callId];
  }
  function _peerShortIdForFp(fp) {
    if (!fp) return null;
    for (const p of state.peers.values()) {
      if (p.fingerprint === fp) return p.short_id;
    }
    return null;
  }
  function _renderMissedCallBubble(callId, t, endCause) {
    const peerShortId = _peerShortIdForFp(t.peerFp) || t.peerFp || "";
    if (!peerShortId) return;
    const labelByCause = {
      peer_declined: "Declined",
      invite_timeout: "No answer",
      user_hangup_local: "Cancelled",
      network_async_conversion: "Could not connect",
    };
    const msg = {
      id: `missed-${callId}`,
      t: "CALL_LOG",
      ts: t.startedMs,
      dir: t.direction === "out" ? "out" : "in",
      peer: peerShortId,
      peer_fp: t.peerFp,
      call_kind: t.kind || "voice",
      call_outcome: "missed",
      call_end_cause: endCause || "",
      call_end_label: labelByCause[endCause] || "No answer",
      call_duration_s: 0,
    };
    state.messages.push(msg);
    if (state.messages.length > 1000) state.messages = state.messages.slice(-800);
    if (msg.peer === state.selectedPeer) renderMessages();
  }
  function _renderEndedCallBubble(callId, t, endCause) {
    const peerShortId = _peerShortIdForFp(t.peerFp) || t.peerFp || "";
    if (!peerShortId) return;
    const durSec = Math.max(0, Math.round((t.endedAt - t.startedMs) / 1000));
    const durLabel = durSec >= 60
      ? `${Math.floor(durSec / 60)}m ${durSec % 60}s`
      : `${durSec}s`;
    const msg = {
      id: `ended-${callId}`,
      t: "CALL_LOG",
      ts: t.startedMs,
      dir: t.direction === "out" ? "out" : "in",
      peer: peerShortId,
      peer_fp: t.peerFp,
      call_kind: t.kind || "voice",
      call_outcome: "ended",
      call_end_cause: endCause || "",
      call_end_label: durLabel,
      call_duration_s: durSec,
    };
    state.messages.push(msg);
    if (state.messages.length > 1000) state.messages = state.messages.slice(-800);
    if (msg.peer === state.selectedPeer) renderMessages();
  }

  window.handleLivingPresenceCallEvent = function (m) {
    if (!m || m.type !== "call_event") return false;
    const tail = m.tail_kind;
    const callId = m.call_id;
    if (tail === "show_ring") {
      if (callUI.acceptedCallIds.has(callId) || callUI.activeCallId === callId) {
        const now = Date.now();
        const last = Number(callUI.lastAcceptRetryMs[callId] || 0);
        if (now - last > 3000) {
          callUI.lastAcceptRetryMs[callId] = now;
          callApiPost({ action: "accept", call_id: callId }).catch(() => {});
          reportCallEvent("accept_resend", { reason: "duplicate_ring" });
        }
        return true;
      }
      callUI.inboundCallId = callId;
      callUI.inboundCallPeer = (m.peer_label || callId.slice(0, 8));
      callUI.inboundCallPeerFp = m.peer_master_vk_hex || null;
      resolveSimultaneousCallIfNeeded(callId, callUI.inboundCallPeerFp);
      _trackCallStart(callId, {
        peerLabel: callUI.inboundCallPeer,
        peerFp: callUI.inboundCallPeerFp,
        direction: "in",
        kind: m.kind || "voice",
      });
      showIncomingRing(callUI.inboundCallPeer);
      return true;
    }
    if (tail === "phase_changed") {
      const phase = m.new_phase;
      if (phase === "active") {
        _markCallActive(callId);
        hideOutgoingOverlay();
        hideIncomingRing();
        if (!callUI.activeCallId) {
          callUI.activeCallId = callId;
          callUI.activeCallPeer = callId.slice(0, 8);
        }
        if (m.peer_master_vk_hex) callUI.activeCallPeerFp = m.peer_master_vk_hex;
        callUI.activeCallLocalRole = callUI.activeCallLocalRole || "originator";
        showActiveSurface(callUI.activeCallPeer, "");
        ensureMediaNegotiation("active");
      } else if (phase === "async_capture") {
        hideOutgoingOverlay();
        hideIncomingRing();
        if (!callUI.activeCallId) callUI.activeCallId = callId;
        beginCapsuleCapture(callId);
        updateOneChip("#call-one-engine", "Capsule");
        addOneCallEvent("Keep talking, then choose Save capsule when you're done.");
      } else if (phase === "ended" || phase === "resumable") {
        _resolveCallEnded(callId, m.end_cause || "");
        hideOutgoingOverlay();
        hideIncomingRing();
        hideActiveSurface();
        if (capsuleCapture.active && capsuleCapture.callId === callId) {
          resetCapsuleCapture();
        }
        stopAllMedia();
        if (callUI.activeCallId === callId) callUI.activeCallId = null;
        if (callUI.activeCallId === null) callUI.activeCallPeerFp = null;
        if (callUI.activeCallId === null) callUI.activeCallLocalRole = "";
      }
      return true;
    }
    if (tail === "recording_state_changed") {
      // recording_state: int (matches RecordingState enum).
      // 3 = RECORDING_MUTUAL. Any other = NOT_RECORDING-ish.
      if (m.recording_state === 3) showRecordingBadge();
      else hideRecordingBadge();
      return true;
    }
    if (tail === "resume_offer_available") {
      // The chat surface will render a resume affordance - no
      // overlay needed here (the call is no longer live).
      if (typeof toast === "function") {
        toast("Voice note saved. You can pick up where you left off.", "info", 4000);
      }
      return true;
    }
    if (tail === "sdp_offer") {
      // Recipient side: peer's SDP offer arrived. Track it so we
      // setRemoteDescription + createAnswer once we accept.
      callUI.pendingRemoteOffer = m.sdp || "";
      addOneCallEvent("Media offer received.");
      reportCallEvent("remote_offer_received");
      if (callUI.activeCallId === callId && media.pc && callUI.localMediaReady) {
        callUI.pendingRemoteOffer = null;
        applyRemoteSdpOffer(m.sdp);
      }
      return true;
    }
    if (tail === "sdp_answer") {
      addOneCallEvent("Media answer received.");
      reportCallEvent("remote_answer_received");
      applyRemoteSdpAnswer(m.sdp);
      return true;
    }
    if (tail === "ice_candidate") {
      applyRemoteIceCandidate(m);
      return true;
    }
    if (tail === "call_refused") {
      hideIncomingRing();
      hideOutgoingOverlay();
      hideActiveSurface();
      stopAllMedia();
      if (callUI.activeCallId === callId) callUI.activeCallId = null;
      if (callUI.activeCallId === null) callUI.activeCallLocalRole = "";
      if (callUI.inboundCallId === callId) callUI.inboundCallId = null;
      if (typeof toast === "function") {
        toast(m.user_message || "Call refused.", "warn", 6000);
      }
      return true;
    }
    if (tail === "sas_verification_required") {
      const pane = $$("#call-sas-pane");
      const words = $$("#call-sas-words");
      const phrase = String(m.sas_words || m.sas || "").trim();
      if (words) {
        words.textContent = phrase || "No verification words were supplied. Do not tap Yes yet.";
      }
      reportCallEvent(phrase ? "sas_words_shown" : "sas_words_missing");
      if (pane) {
        pane.style.display = "block";
        pane.classList.add("show");
      }
      return true;
    }
    if (tail === "frame_attestation") {
      // Tier β - Reality dot live update.
      // m.verified: bool. m.kind: "Original" | "Repaired" | etc. (UI words).
      if (typeof window.updateRealityDot === "function") {
        window.updateRealityDot({
          callId,
          verified: m.verified,
          kind: m.kind,
          path: m.path,
          recording: m.recording,
        });
      }
      updateOneChip("#call-one-reality", m.verified ? "Confirmed" : "Unconfirmed");
      addOneCallEvent(m.verified
        ? "Sender signature confirmed this exact media window; this is not physical-scene attestation."
        : "The sender signature for this media window is not confirmed.");
      return true;
    }
    // ── Tier δ - Immune System actions ───────────────────────────
    if (tail === "immune_lower_fidelity") {
      // Drop the outbound video bitrate. RTCRtpSender.setParameters
      // takes a few hundred ms to negotiate, but the codec ramp is
      // smooth - no visible glitch.
      const targetKbps = m.target_video_bitrate_kbps || 200;
      updateOneChip("#call-one-engine", "Adaptive");
      addOneCallEvent("One Link lowered video bitrate to keep the call smooth.");
      if (media.pc) {
        media.pc.getSenders().forEach((sender) => {
          if (!sender.track || sender.track.kind !== "video") return;
          try {
            const params = sender.getParameters();
            if (!params.encodings) params.encodings = [{}];
            params.encodings[0].maxBitrate = targetKbps * 1000;
            sender.setParameters(params);
          } catch (_) { /* older browser */ }
        });
      }
      return true;
    }
    if (tail === "immune_voice_only") {
      // Disable the video track entirely. Track stays connected
      // (DTLS-SRTP doesn't churn) but emits black frames.
      if (media.localStream) {
        media.localStream.getVideoTracks().forEach((t) => {
          t.enabled = false;
        });
      }
      updateOneChip("#call-one-engine", "Voice first");
      addOneCallEvent("Camera paused automatically so the conversation stays clear.");
      if (typeof toast === "function" && m.user_message) {
        toast(m.user_message, "info", 5000);
      }
      return true;
    }
    if (tail === "immune_convert_to_async") {
      // The call is converting to a voice-note. Browser stops sending
      // RTC packets + starts capsule MediaRecorder; daemon's lifecycle
      // has already advanced to ASYNC_CAPTURE.
      if (typeof toast === "function" && m.user_message) {
        toast(m.user_message, "info", 8000);
      }
      updateOneChip("#call-one-engine", "Capsule");
      addOneCallEvent("One Link is preserving the conversation as a resumable voice capsule.");
      beginCapsuleCapture(callId);
      return true;
    }
    if (tail === "immune_prewarm_route") {
      updateOneChip("#call-one-route", "Preparing");
      addOneCallEvent("One Link is warming a stronger path in the background.");
      // Tier ε - no UI yet; the Route Brain owns this. The hook is
      // here so the next tier doesn't need an additional dispatch.
      return true;
    }
    if (tail === "immune_suggest_handoff") {
      updateOneChip("#call-one-engine", "Handoff");
      addOneCallEvent(m.user_message || "One Link found a better device for this call.");
      if (typeof toast === "function" && m.user_message) {
        toast(m.user_message, "info", 8000);
      }
      return true;
    }
    if (tail === "immune_switch_route" || tail === "immune_rekey") {
      updateOneChip("#call-one-route", tail === "immune_rekey" ? "Refreshed" : "Switched");
      addOneCallEvent(tail === "immune_rekey"
        ? "Secure connection refreshed."
        : "One Link moved the call to a better route.");
      // Quiet acks - the underlying switch happens daemon-side.
      return true;
    }
    return false;
  };
