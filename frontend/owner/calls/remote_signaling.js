  function rebuildPeerConnectionForRemoteOffer() {
    const localStream = media.localStream;
    if (media.pc) {
      try { media.pc.close(); } catch (_) {}
      media.pc = null;
    }
    media.iceConfigReady = null;
    callUI.pendingIceCandidates = [];
    callUI.appliedIceKeys.clear();
    const pc = setupRtcPeerConnection();
    if (!pc) return false;
    if (localStream) ensureLocalTracksOnPeerConnection();
    return true;
  }

  async function ensureLocalTracksOnPeerConnectionSettled() {
    if (!media.pc || !media.localStream) return false;
    ensureLocalTracksOnPeerConnection();
    const liveTracks = media.localStream.getTracks()
      .filter((t) => t.readyState === "live");
    const transceivers = media.pc.getTransceivers ? media.pc.getTransceivers() : [];
    const replacements = [];
    liveTracks.forEach((track) => {
      const tx = transceivers.find((candidate) => (
        candidate
        && candidate.sender
        && candidate.receiver
        && candidate.receiver.track
        && candidate.receiver.track.kind === track.kind
        && candidate.sender.track !== track
        && typeof candidate.sender.replaceTrack === "function"
      ));
      if (!tx) return;
      try {
        replacements.push(tx.sender.replaceTrack(track));
        if (tx.direction && tx.direction !== "sendrecv") tx.direction = "sendrecv";
      } catch (_) {}
    });
    if (replacements.length) {
      try { await Promise.allSettled(replacements); } catch (_) {}
    }
    return liveTracks.length > 0;
  }

  function isLocalOfferOwner() {
    const role = String(callUI.activeCallLocalRole || "").toLowerCase();
    if (role === "recipient" || role === "answerer") return false;
    if (role === "originator" || role === "caller") return true;
    return !callUI.inboundCallId;
  }

  async function recoverRemoteOfferCollision(sdp, key) {
    callUI.remoteOfferCollisionCount += 1;
    const ageMs = Date.now() - Number(callUI.lastLocalOfferCreatedMs || 0);
    const shouldRecover = callUI.remoteOfferCollisionCount >= 2 || ageMs > 7000;
    reportCallEvent("offer_collision", {
      collision_count: callUI.remoteOfferCollisionCount,
      offer_age_ms: Math.max(0, ageMs),
      recovering: shouldRecover,
    });
    if (!shouldRecover) {
      await resendLocalSdpOffer("offer_collision");
      return false;
    }
    addOneCallEvent("Repairing media handshake...");
    reportCallEvent("offer_collision_recovery_start", {
      collision_count: callUI.remoteOfferCollisionCount,
      offer_age_ms: Math.max(0, ageMs),
    });
    try {
      await media.pc.setLocalDescription({ type: "rollback" });
      reportCallEvent("offer_collision_rollback");
    } catch (_) {
      reportCallEvent("offer_collision_rebuild");
      if (!rebuildPeerConnectionForRemoteOffer()) return false;
    }
    try {
      await media.pc.setRemoteDescription({ type: "offer", sdp });
      if (key) callUI.appliedRemoteOfferKeys.add(key);
      callUI.remoteOfferCollisionCount = 0;
      callUI.lastLocalOfferSdp = "";
      callUI.lastOfferSendMs = 0;
      callUI.lastLocalOfferCreatedMs = 0;
      await flushPendingIceCandidates();
      await sendLocalSdpAnswer();
      reportCallEvent("offer_collision_recovered");
      return true;
    } catch (_) {
      reportCallEvent("offer_collision_recovery_failed", {
        state: media.pc && media.pc.signalingState,
      });
      return false;
    }
  }

  async function applyRemoteSdpOffer(sdp) {
    if (!sdp) return;
    if (!media.pc) setupRtcPeerConnection();
    const key = sdpKey(sdp);
    if (
      key
      && media.pc.localDescription
      && media.pc.localDescription.type === "offer"
      && sdpKey(media.pc.localDescription.sdp) === key
    ) {
      reportCallEvent("remote_offer_echo_ignored");
      await resendLocalSdpOffer("offer_echo");
      return;
    }
    if (key && callUI.appliedRemoteOfferKeys.has(key)) {
      const hasLocalAnswer = !!(
        callUI.lastLocalAnswerSdp
        || (media.pc.localDescription && media.pc.localDescription.type === "answer")
      );
      reportCallEvent("duplicate_remote_offer_ignored", {
        reason: hasLocalAnswer ? "answered" : "no_answer",
      });
      if (!hasLocalAnswer) await resendLocalSdpAnswer("duplicate_offer");
      return;
    }
    if (
      media.pc.remoteDescription
      && media.pc.remoteDescription.type === "offer"
      && sdpKey(media.pc.remoteDescription.sdp) === key
    ) {
      if (key) callUI.appliedRemoteOfferKeys.add(key);
      const hasLocalAnswer = !!(
        callUI.lastLocalAnswerSdp
        || (media.pc.localDescription && media.pc.localDescription.type === "answer")
      );
      reportCallEvent("duplicate_remote_offer_ignored", {
        reason: hasLocalAnswer ? "answered" : "no_answer",
      });
      if (!hasLocalAnswer) await resendLocalSdpAnswer("duplicate_offer");
      return;
    }
    if (media.pc.signalingState && media.pc.signalingState !== "stable") {
      if (
        media.pc.signalingState === "have-local-offer"
        && media.pc.localDescription
        && media.pc.localDescription.type === "offer"
      ) {
        if (isLocalOfferOwner()) {
          reportCallEvent("remote_offer_rejected_by_role", {
            role: callUI.activeCallLocalRole || "originator",
            signaling_state: media.pc.signalingState || "",
          });
          await resendLocalSdpOffer("unexpected_remote_offer");
        } else {
          await recoverRemoteOfferCollision(sdp, key);
        }
      }
      return;
    }
    try {
      await media.pc.setRemoteDescription({ type: "offer", sdp });
      if (key) callUI.appliedRemoteOfferKeys.add(key);
      callUI.remoteOfferCollisionCount = 0;
      await flushPendingIceCandidates();
      await sendLocalSdpAnswer();
    } catch (_) { /* fall through */ }
  }

  async function applyRemoteSdpAnswer(sdp) {
    if (!sdp || !media.pc) return;
    const key = sdpKey(sdp);
    if (key && callUI.appliedRemoteAnswerKeys.has(key)) return;
    if (
      media.pc.remoteDescription
      && media.pc.remoteDescription.type === "answer"
      && sdpKey(media.pc.remoteDescription.sdp) === key
    ) {
      if (key) callUI.appliedRemoteAnswerKeys.add(key);
      return;
    }
    if (media.pc.signalingState !== "have-local-offer") return;
    try {
      await media.pc.setRemoteDescription({ type: "answer", sdp });
      if (key) callUI.appliedRemoteAnswerKeys.add(key);
      callUI.remoteOfferCollisionCount = 0;
      await flushPendingIceCandidates();
    } catch (_) { /* fall through */ }
  }

  async function applyRemoteIceCandidate(data) {
    const iceKey = data && `${data.call_id || callUI.activeCallId || ""}|${data.sdp_mid || ""}|${data.sdp_m_line_index ?? ""}|${data.candidate || ""}|${data.end_of_candidates ? "end" : ""}`;
    if (!media.pc || !media.pc.remoteDescription) {
      if (!iceKey || !callUI.pendingIceCandidates.some((item) => (
        `${item.call_id || callUI.activeCallId || ""}|${item.sdp_mid || ""}|${item.sdp_m_line_index ?? ""}|${item.candidate || ""}|${item.end_of_candidates ? "end" : ""}`
      ) === iceKey)) {
        callUI.pendingIceCandidates.push(data);
      }
      return;
    }
    if (iceKey && callUI.appliedIceKeys.has(iceKey)) return;
    if (iceKey) callUI.appliedIceKeys.add(iceKey);
    // end_of_candidates → addIceCandidate(null) signals completion.
    if (data && data.end_of_candidates) {
      try { await media.pc.addIceCandidate(null); } catch (_) {}
      return;
    }
    try {
      await media.pc.addIceCandidate({
        candidate: data.candidate,
        sdpMid: data.sdp_mid,
        sdpMLineIndex: data.sdp_m_line_index,
      });
    } catch (_) { /* candidate may arrive before remote description */ }
  }

  async function flushPendingIceCandidates() {
    if (!media.pc || !media.pc.remoteDescription) return;
    const queued = callUI.pendingIceCandidates.splice(0);
    for (const item of queued) {
      await applyRemoteIceCandidate(item);
    }
  }

