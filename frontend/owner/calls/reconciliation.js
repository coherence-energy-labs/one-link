  async function acceptInboundCall() {
    if (!callUI.inboundCallId) return;
    const inboundCallId = callUI.inboundCallId;
    const inboundPeer = callUI.inboundCallPeer;
    const inboundPeerFp = callUI.inboundCallPeerFp;
    callState.acceptCall(inboundCallId);
    hideIncomingRing();
    callState.update({
      activeCallId: inboundCallId,
      activeCallPeer: inboundPeer,
      activeCallPeerFp: inboundPeerFp,
      activeCallLocalRole: "recipient",
    });
    showActiveSurface(inboundPeer, "");
    setupRtcPeerConnection();
    callState.set("localMediaReady", false);
    mediaState.update({
      expectRemoteAudio: true,
      expectRemoteVideo: true,
    });
    const mediaPromise = startLocalMedia({ audio: true, video: true });
    const result = await callApiPost({
      action: "accept", call_id: inboundCallId,
    });
    reportCallEvent(result && result.ok ? "accept_sent" : "accept_failed", {
      ok: !!(result && result.ok),
    });
    if (result.ok) {
      const stream = await mediaPromise;
      if (stream && media.pc) {
        await ensureLocalTracksOnPeerConnectionSettled();
        startAttestStream(stream);
      }
      callState.set("localMediaReady", true);
      reportCallEvent("local_media_ready", { reason: "accept" });
      if (callUI.pendingRemoteOffer) {
        const offerSdp = callUI.pendingRemoteOffer;
        callState.set("pendingRemoteOffer", null);
        await applyRemoteSdpOffer(offerSdp);
      } else {
        addOneCallEvent("Waiting for media offer...");
        reportCallEvent("waiting_for_media_offer", { reason: "accept" });
        setTimeout(() => { backfillLivingPresenceCalls().catch(() => {}); }, 250);
      }
    } else {
      callState.forgetAcceptedCall(inboundCallId);
      callState.set("localMediaReady", false);
      hideActiveSurface();
      stopAllMedia();
      callState.update({
        activeCallId: null,
        activeCallPeer: null,
        activeCallPeerFp: null,
        activeCallLocalRole: "",
      });
      if (typeof toast === "function") toast(result.user_message, "warn");
    }
    callState.update({
      inboundCallId: null,
      inboundCallPeerFp: null,
    });
  }

  async function rejoinActiveCallFromSnapshot(call, reason) {
    if (!call || !call.call_id) return false;
    const callId = call.call_id;
    const now = Date.now();
    const last = Number(callUI.lastRejoinAttemptMs[callId] || 0);
    if (now - last < 3000) return false;
    callState.stampRejoinAttempt(callId, now);
    const peerLabel = peerLabelFromCall(call);
    callState.update({
      activeCallId: callId,
      activeCallPeer: peerLabel,
    });
    callState.set("activeCallPeerFp", call.peer_master_vk_hex || callUI.activeCallPeerFp);
    callState.set("activeCallLocalRole", call.local_role || (call.is_incoming ? "recipient" : "originator"));
    callState.acceptCall(callId);
    const wantsVideo = String(call.kind || call.call_kind || callUI.activeCallKind || "video").toLowerCase() !== "voice";
    callState.set("activeCallKind", wantsVideo ? "video" : "voice");
    mediaState.update({
      expectRemoteAudio: true,
      expectRemoteVideo: wantsVideo,
    });
    hideOutgoingOverlay();
    hideIncomingRing();
    showActiveSurface(peerLabel, "");
    const snapshot = await callApiPost({
      action: "rejoin",
      call_id: callId,
      reason: reason || "browser_rejoin",
    });
    if (!snapshot || snapshot.ok !== true) {
      reportCallEvent("client_rejoin_failed", { reason: reason || "browser_rejoin" });
      return false;
    }
    setupRtcPeerConnection();
    callState.set("localMediaReady", false);
    const stream = await startLocalMedia({ audio: true, video: wantsVideo });
    if (stream && media.pc) {
      await ensureLocalTracksOnPeerConnectionSettled();
      startAttestStream(stream);
      callState.set("localMediaReady", true);
      reportCallEvent("client_rejoin_media_ready", {
        reason: reason || "browser_rejoin",
        ok: true,
      });
    }
    const pendingIce = Array.isArray(snapshot.pending_ice_candidates)
      ? snapshot.pending_ice_candidates
      : [];
    if (snapshot.pending_sdp_offer) {
      await applyRemoteSdpOffer(snapshot.pending_sdp_offer);
    } else if (snapshot.pending_sdp_answer) {
      await applyRemoteSdpAnswer(snapshot.pending_sdp_answer);
    }
    for (const candidate of pendingIce) {
      await applyRemoteIceCandidate({
        call_id: callId,
        peer_master_vk_hex: snapshot.peer_master_vk_hex || call.peer_master_vk_hex,
        ...candidate,
      });
    }
    if (
      media.pc
      && media.localStream
      && !media.pc.remoteDescription
      && !snapshot.pending_sdp_offer
    ) {
      await ensureMediaNegotiation("rejoin");
    }
    startCallTelemetry();
    return true;
  }

  async function resolveSimultaneousCallIfNeeded(inboundCallId, inboundPeerFp) {
    if (!inboundCallId || !inboundPeerFp) return false;
    if (!callUI.activeCallId || !callUI.activeCallPeerFp) return false;
    if (callUI.activeCallPeerFp !== inboundPeerFp) return false;
    if (callUI.activeCallId === inboundCallId) return false;
    const keepInbound = String(inboundCallId) < String(callUI.activeCallId);
    if (keepInbound) {
      const oldCallId = callUI.activeCallId;
      await callApiPost({ action: "hangup", call_id: oldCallId });
      hideOutgoingOverlay();
      hideActiveSurface();
      stopAllMedia();
      callState.set("activeCallId", null);
      await acceptInboundCall();
      return true;
    }
    await callApiPost({ action: "decline", call_id: inboundCallId });
    if (callUI.inboundCallId === inboundCallId) {
      callState.update({
        inboundCallId: null,
        inboundCallPeer: null,
        inboundCallPeerFp: null,
      });
    }
    return true;
  }

  async function backfillLivingPresenceCalls() {
    // Reconciliation may showIncomingRing(), hideOutgoingOverlay(), and
    // hideIncomingRing(); the WebSocket remains the primary event path.
    const payload = await callApiList();
    const calls = Array.isArray(payload && payload.calls) ? payload.calls : [];
    const visibleCallIds = new Set(calls.map((c) => c && c.call_id).filter(Boolean));
    if (callUI.activeCallId && !visibleCallIds.has(callUI.activeCallId)) {
      hideOutgoingOverlay();
      hideIncomingRing();
      hideActiveSurface();
      if (capsuleCapture.active) resetCapsuleCapture();
      stopAllMedia();
      stopCallTelemetry();
      callState.update({
        activeCallId: null,
        activeCallPeer: null,
        activeCallPeerFp: null,
        activeCallLocalRole: "",
        inboundCallId: null,
        inboundCallPeer: null,
        inboundCallPeerFp: null,
      });
    }
    let inboundStillRinging = false;
    for (const call of calls) {
      if (!call || !call.call_id) continue;
      const phase = String(call.phase || "").toLowerCase();
      const incoming = !!call.is_incoming || call.local_role === "recipient";
      if (incoming && call.pending_sdp_offer && !callUI.pendingRemoteOffer) {
        callState.set("pendingRemoteOffer", call.pending_sdp_offer);
      }
      if (!incoming && call.pending_sdp_answer && media.pc) {
        callState.set("activeCallLocalRole", call.local_role || callUI.activeCallLocalRole || "originator");
        applyRemoteSdpAnswer(call.pending_sdp_answer);
      }
      const pendingIce = Array.isArray(call.pending_ice_candidates)
        ? call.pending_ice_candidates
        : [];
      for (const candidate of pendingIce) {
        await applyRemoteIceCandidate({
          call_id: call.call_id,
          peer_master_vk_hex: call.peer_master_vk_hex,
          ...candidate,
        });
      }
      if (incoming && phase === "ringing") {
        if (
          callUI.acceptedCallIds.has(call.call_id)
          || callUI.activeCallId === call.call_id
        ) {
          inboundStillRinging = callUI.inboundCallId === call.call_id;
          const now = Date.now();
          const last = Number(callUI.lastAcceptRetryMs[call.call_id] || 0);
          if (now - last > 3000) {
            callState.stampAcceptRetry(call.call_id, now);
            callApiPost({ action: "accept", call_id: call.call_id }).catch(() => {});
            reportCallEvent("accept_resend", { reason: "ringing_backfill" });
          }
          continue;
        }
        inboundStillRinging = true;
        if (callUI.inboundCallId !== call.call_id) {
          callState.set("inboundCallId", call.call_id);
          callState.set("inboundCallPeer", peerLabelFromCall(call));
          callState.set("inboundCallPeerFp", call.peer_master_vk_hex || null);
        }
        if (await resolveSimultaneousCallIfNeeded(
          callUI.inboundCallId,
          callUI.inboundCallPeerFp,
        )) {
          continue;
        }
        showIncomingRing(callUI.inboundCallPeer || peerLabelFromCall(call));
        continue;
      }
      if (phase === "active") {
        callState.acceptCall(call.call_id);
        if (!callUI.activeCallId || callUI.activeCallId === call.call_id) {
          callState.set("activeCallId", call.call_id);
          callState.set("activeCallPeer", peerLabelFromCall(call));
          callState.set("activeCallPeerFp", call.peer_master_vk_hex || callUI.activeCallPeerFp);
          callState.set("activeCallLocalRole", call.local_role || (incoming ? "recipient" : "originator"));
          hideOutgoingOverlay();
          hideIncomingRing();
          showActiveSurface(callUI.activeCallPeer, "");
        }
        if (!media.pc || !media.localStream || !callUI.localMediaReady) {
          await rejoinActiveCallFromSnapshot(call, "backfill_active");
          continue;
        }
        if (incoming && call.pending_sdp_offer && media.pc) {
          applyRemoteSdpOffer(call.pending_sdp_offer);
        }
        continue;
      }
      if (phase === "async_capture") {
        hideOutgoingOverlay();
        hideIncomingRing();
        callState.set("activeCallId", call.call_id);
        callState.set("activeCallPeer", peerLabelFromCall(call));
        callState.set("activeCallPeerFp", call.peer_master_vk_hex || callUI.activeCallPeerFp);
        callState.set("activeCallLocalRole", call.local_role || callUI.activeCallLocalRole);
        showActiveSurface(callUI.activeCallPeer, "Voice capsule");
        if (!media.localStream) {
          const stream = await startLocalMedia({ audio: true, video: false });
          if (stream) startAttestStream(stream);
        }
        beginCapsuleCapture(call.call_id);
        continue;
      }
      if (
        call.call_id === callUI.inboundCallId &&
        (phase === "ended" || phase === "resumable")
      ) {
        hideIncomingRing();
        callState.update({
          inboundCallId: null,
          inboundCallPeer: null,
          inboundCallPeerFp: null,
        });
      }
      if (
        call.call_id === callUI.activeCallId &&
        (phase === "ended" || phase === "resumable")
      ) {
        hideOutgoingOverlay();
        hideActiveSurface();
        stopAllMedia();
        stopCallTelemetry();
        callState.update({
          activeCallId: null,
          activeCallPeer: null,
          activeCallPeerFp: null,
          activeCallLocalRole: "",
        });
      }
    }
    if (callUI.inboundCallId && !inboundStillRinging) {
      const matching = calls.find((c) => c && c.call_id === callUI.inboundCallId);
      if (!matching) {
        hideIncomingRing();
        callState.update({
          inboundCallId: null,
          inboundCallPeer: null,
          inboundCallPeerFp: null,
        });
      }
    }
  }
  window.backfillLivingPresenceCalls = backfillLivingPresenceCalls;

