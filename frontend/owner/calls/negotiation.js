  async function sendLocalSdpOffer() {
    if (!media.pc || !callUI.activeCallId) return;
    if (!isLocalOfferOwner()) {
      reportCallEvent("offer_suppressed_by_role", {
        role: callUI.activeCallLocalRole || "unknown",
      });
      return;
    }
    if (callUI.sdpOfferInFlight) return;
    try {
      callUI.sdpOfferInFlight = true;
      addOneCallEvent("Preparing media offer...");
      reportCallEvent("offer_preparing");
      if (media.iceConfigReady) await media.iceConfigReady;
      ensureMediaTransceivers();
      await ensureLocalTracksOnPeerConnectionSettled();
      const offer = await media.pc.createOffer();
      await media.pc.setLocalDescription(offer);
      callUI.lastLocalOfferSdp = offer.sdp || "";
      callUI.lastOfferSendMs = Date.now();
      callUI.lastLocalOfferCreatedMs = callUI.lastOfferSendMs;
      callUI.remoteOfferCollisionCount = 0;
      const result = await callApiPost({
        action: "send_sdp_offer",
        call_id: callUI.activeCallId,
        sdp: offer.sdp,
      });
      addOneCallEvent(result && result.ok
        ? "Media offer sent."
        : "Media offer could not reach the other device.");
      reportCallEvent(result && result.ok ? "offer_sent" : "offer_send_failed", {
        ok: !!(result && result.ok),
      });
    } catch (e) {
      addOneCallEvent(`Media offer failed: ${e && e.name ? e.name : "error"}.`);
      reportCallEvent("offer_send_failed", { ok: false });
    } finally {
      callUI.sdpOfferInFlight = false;
    }
  }

  async function resendLocalSdpOffer(reason) {
    if (!media.pc || !callUI.activeCallId || callUI.sdpOfferInFlight) return;
    if (!isLocalOfferOwner()) {
      reportCallEvent("offer_resend_suppressed_by_role", {
        reason: reason || "watchdog",
        role: callUI.activeCallLocalRole || "unknown",
      });
      return;
    }
    const sdp = (
      callUI.lastLocalOfferSdp
      || (media.pc.localDescription && media.pc.localDescription.type === "offer"
        ? media.pc.localDescription.sdp
        : "")
    );
    if (!sdp) return;
    const now = Date.now();
    if (now - callUI.lastOfferSendMs < 3000) return;
    try {
      callUI.sdpOfferInFlight = true;
      callUI.lastOfferSendMs = now;
      addOneCallEvent("Resending media offer...");
      reportCallEvent("offer_resend", { reason: reason || "watchdog" });
      const result = await callApiPost({
        action: "send_sdp_offer",
        call_id: callUI.activeCallId,
        sdp,
      });
      reportCallEvent(result && result.ok ? "offer_resent" : "offer_resend_failed", {
        ok: !!(result && result.ok),
        reason: reason || "watchdog",
      });
    } catch (_) {
      reportCallEvent("offer_resend_failed", { ok: false, reason: reason || "watchdog" });
    } finally {
      callUI.sdpOfferInFlight = false;
    }
  }

  function ensureLocalTracksOnPeerConnection() {
    if (!media.pc || !media.localStream) return false;
    const liveTracks = media.localStream.getTracks()
      .filter((t) => t.readyState === "live");
    if (!liveTracks.length) return false;
    const transceivers = media.pc.getTransceivers ? media.pc.getTransceivers() : [];
    liveTracks.forEach((track) => {
      const tx = transceivers.find((candidate) => (
        candidate
        && candidate.sender
        && candidate.receiver
        && candidate.receiver.track
        && candidate.receiver.track.kind === track.kind
        && candidate.sender.track !== track
      ));
      if (!tx || !tx.sender || typeof tx.sender.replaceTrack !== "function") return;
      try {
        tx.sender.replaceTrack(track);
        if (tx.direction && tx.direction !== "sendrecv") tx.direction = "sendrecv";
      } catch (_) {}
    });
    const alreadyAttached = new Set(
      (media.pc.getSenders ? media.pc.getSenders() : [])
        .map((s) => s && s.track)
        .filter(Boolean),
    );
    liveTracks.forEach((track) => {
      if (alreadyAttached.has(track)) return;
      try { media.pc.addTrack(track, media.localStream); } catch (_) {}
    });
    return true;
  }

  function reviveRemotePlayback(reason) {
    const now = Date.now();
    if (now - Number(callUI.lastPlaybackReviveMs || 0) < 2500) return;
    callUI.lastPlaybackReviveMs = now;
    syncRemoteMediaSurface(reason || "playback_revive");
    reportCallEvent("remote_playback_revive", { reason: reason || "watchdog" });
  }

  async function rebuildPeerConnectionForActiveCall(reason) {
    if (!callUI.activeCallId || !media.localStream) return false;
    const now = Date.now();
    if (now - Number(callUI.lastPcRebuildMs || 0) < 30000) return false;
    callUI.lastPcRebuildMs = now;
    addOneCallEvent("Rebuilding media engine...");
    reportCallEvent("pc_rebuild_start", { reason: reason || "watchdog" });
    const remoteTracks = media.remoteStream ? media.remoteStream.getTracks() : [];
    remoteTracks.forEach((track) => {
      try { media.remoteStream.removeTrack(track); } catch (_) {}
    });
    attachRemoteStream(media.remoteStream || new MediaStream());
    if (media.pc) {
      try { media.pc.close(); } catch (_) {}
      media.pc = null;
    }
    media.iceConfigReady = null;
    media.transceiversReady = false;
    callUI.pendingIceCandidates = [];
    callUI.appliedIceKeys.clear();
    callUI.appliedRemoteOfferKeys.clear();
    callUI.appliedRemoteAnswerKeys.clear();
    callUI.sdpOfferInFlight = false;
    callUI.sdpAnswerInFlight = false;
    callUI.lastLocalOfferSdp = "";
    callUI.lastLocalAnswerSdp = "";
    const pc = setupRtcPeerConnection();
    if (!pc) return false;
    ensureLocalTracksOnPeerConnection();
    await sendLocalSdpOffer();
    reportCallEvent("pc_rebuild_offer_sent", { reason: reason || "watchdog" });
    return true;
  }

  function sdpKey(sdp) {
    const text = String(sdp || "");
    if (!text) return "";
    return `${text.length}:${text.slice(0, 96)}:${text.slice(-96)}`;
  }

  async function sendLocalSdpAnswer() {
    if (!media.pc || !callUI.activeCallId) return;
    if (callUI.sdpAnswerInFlight) return;
    try {
      callUI.sdpAnswerInFlight = true;
      addOneCallEvent("Preparing media answer...");
      reportCallEvent("answer_preparing");
      if (media.iceConfigReady) await media.iceConfigReady;
      ensureMediaTransceivers();
      await ensureLocalTracksOnPeerConnectionSettled();
      const answer = await media.pc.createAnswer();
      await media.pc.setLocalDescription(answer);
      callUI.lastLocalAnswerSdp = answer.sdp || "";
      callUI.lastAnswerSendMs = Date.now();
      const result = await callApiPost({
        action: "send_sdp_answer",
        call_id: callUI.activeCallId,
        sdp: answer.sdp,
      });
      addOneCallEvent(result && result.ok
        ? "Media answer sent."
        : "Media answer could not reach the other device.");
      reportCallEvent(result && result.ok ? "answer_sent" : "answer_send_failed", {
        ok: !!(result && result.ok),
      });
    } catch (e) {
      addOneCallEvent(`Media answer failed: ${e && e.name ? e.name : "error"}.`);
      reportCallEvent("answer_send_failed", { ok: false });
    } finally {
      callUI.sdpAnswerInFlight = false;
    }
  }

  async function resendLocalSdpAnswer(reason) {
    if (!media.pc || !callUI.activeCallId || callUI.sdpAnswerInFlight) return;
    const sdp = (
      callUI.lastLocalAnswerSdp
      || (media.pc.localDescription && media.pc.localDescription.type === "answer"
        ? media.pc.localDescription.sdp
        : "")
    );
    if (!sdp) return;
    const now = Date.now();
    if (now - callUI.lastAnswerSendMs < 3000) return;
    try {
      callUI.sdpAnswerInFlight = true;
      callUI.lastAnswerSendMs = now;
      addOneCallEvent("Resending media answer...");
      reportCallEvent("answer_resend", { reason: reason || "duplicate_offer" });
      const result = await callApiPost({
        action: "send_sdp_answer",
        call_id: callUI.activeCallId,
        sdp,
      });
      reportCallEvent(result && result.ok ? "answer_resent" : "answer_resend_failed", {
        ok: !!(result && result.ok),
        reason: reason || "duplicate_offer",
      });
    } catch (_) {
      reportCallEvent("answer_resend_failed", { ok: false, reason: reason || "duplicate_offer" });
    } finally {
      callUI.sdpAnswerInFlight = false;
    }
  }

  async function ensureMediaNegotiation(reason) {
    if (!callUI.activeCallId || !media.pc || !media.localStream) return;
    if (!isLocalOfferOwner()) {
      reportCallEvent("negotiation_waiting_for_offer_owner", {
        reason: reason || "watchdog",
        role: callUI.activeCallLocalRole || "unknown",
      });
      return;
    }
    const hasLiveLocal = ensureLocalTracksOnPeerConnection();
    if (!hasLiveLocal) return;
    if (!callUI.localMediaReady) {
      callUI.localMediaReady = true;
      reportCallEvent("local_media_ready", { reason: reason || "watchdog" });
    }
    if (
      media.pc.signalingState === "have-local-offer"
      && media.pc.localDescription
      && media.pc.localDescription.type === "offer"
      && !media.pc.remoteDescription
    ) {
      await resendLocalSdpOffer(reason || "watchdog");
      return;
    }
    if (media.pc.localDescription) return;
    if (media.pc.signalingState && media.pc.signalingState !== "stable") return;
    addOneCallEvent(`Media negotiation starting${reason ? ` (${reason})` : ""}.`);
    reportCallEvent("negotiation_starting", { reason });
    await sendLocalSdpOffer();
  }

  function diagnoseMediaRepair(reason) {
    const metrics = callUI.lastMetricsSnapshot || {};
    const ice = String(media.pc?.iceConnectionState || metrics.ice_connection_state || "");
    const conn = String(media.pc?.connectionState || metrics.connection_state || "");
    const signaling = String(media.pc?.signalingState || metrics.signaling_state || "");
    const hasLocal = metrics.has_local_description === true || !!media.pc?.localDescription;
    const hasRemote = metrics.has_remote_description === true || !!media.pc?.remoteDescription;
    const mediaHealth = classifyMediaHealth({
      ...metrics,
      ice_connection_state: ice,
      connection_state: conn,
      signaling_state: signaling,
      has_local_description: hasLocal,
      has_remote_description: hasRemote,
    });
    const remoteMissing = mediaHealth.remote_missing === true;
    const inboundVideoPackets = Number(metrics.inbound_video_packets || 0);
    const inboundAudioPackets = Number(metrics.inbound_audio_packets || 0);
    const remoteVideoReady = Number(metrics.remote_video_ready_state || 0);
    const secondsSinceMoving = callUI.lastRemoteMediaMovingMs
      ? Math.round((Date.now() - Number(callUI.lastRemoteMediaMovingMs || 0)) / 1000)
      : null;
    let kind = "renegotiate";
    let strategy = "ice_restart";
    let severity = 1;
    if (mediaHealth.state === "signaling_incomplete") {
      kind = "signaling_stuck";
      strategy = "resend_sdp";
      severity = 2;
    } else if (mediaHealth.state === "ice_failed") {
      kind = "ice_failed";
      strategy = "ice_restart";
      severity = 3;
    } else if (mediaHealth.state === "ice_unstable") {
      kind = "ice_unstable";
      strategy = "ice_restart";
      severity = 2;
    } else if (mediaHealth.state === "remote_media_missing") {
      kind = "remote_media_missing";
      strategy = "renegotiate";
      severity = 2;
    } else if (mediaHealth.state === "renderer_detached") {
      kind = "renderer_detached";
      strategy = "revive_playback";
      severity = 1;
    } else if (mediaHealth.state === "playback_frozen") {
      kind = "playback_frozen";
      strategy = "revive_playback";
      severity = 1;
    } else if (mediaHealth.state === "media_starved") {
      kind = "media_starved";
      strategy = "renegotiate";
      severity = 2;
    }
    const counts = callUI.repairDiagnosisCounts || {};
    counts[kind] = Number(counts[kind] || 0) + 1;
    callUI.repairDiagnosisCounts = counts;
    callUI.repairEscalationScore = Math.min(10, Number(callUI.repairEscalationScore || 0) + severity);
    if (
      callUI.repairEscalationScore >= 6 ||
      Number(counts[kind] || 0) >= 3 ||
      callUI.mediaRepairStage >= 3
    ) {
      strategy = "rebuild_peer_connection";
    }
    if (
      strategy === "rebuild_peer_connection" &&
      media.iceRelayReady &&
      (media.forceRelayOnRepair || kind === "ice_failed" || kind === "ice_unstable")
    ) {
      strategy = "relay_rebuild";
    }
    const diagnosis = {
      kind,
      strategy,
      severity,
      reason: reason || "watchdog",
      repair_stage: callUI.mediaRepairStage,
      escalation_score: callUI.repairEscalationScore,
      diagnosis_count: counts[kind],
      ice,
      connection: conn,
      signaling,
      has_local_description: hasLocal,
      has_remote_description: hasRemote,
      remote_missing: remoteMissing,
      media_health: mediaHealth,
      seconds_since_media_moving: secondsSinceMoving,
    };
    callUI.lastRepairDiagnosis = diagnosis;
    return diagnosis;
  }

  function markMediaRepairHealthy() {
    callUI.repairEscalationScore = Math.max(0, Number(callUI.repairEscalationScore || 0) - 2);
    if (callUI.repairEscalationScore === 0) {
      callUI.repairDiagnosisCounts = {};
      callUI.lastRepairDiagnosis = null;
    }
  }

  async function repairMediaPath(reason) {
    if (!callUI.activeCallId || !media.pc) return;
    const now = Date.now();
    if (now - Number(callUI.lastMediaRepairMs || 0) < 9000) return;
    callUI.lastMediaRepairMs = now;
    callUI.mediaRepairStage = Math.min(3, Number(callUI.mediaRepairStage || 0) + 1);
    const diagnosis = diagnoseMediaRepair(reason || "watchdog");
    if (now - Number(callUI.lastUserVisibleRepairMs || 0) > 15000 && callUI.qualityBadTicks >= 2) {
      callUI.lastUserVisibleRepairMs = now;
      setReconnectState(true, "Repairing media path...");
    }
    addOneCallEvent("Repairing media path...");
    reportCallEvent("media_path_repair", {
      reason: reason || "watchdog",
      repair_stage: callUI.mediaRepairStage,
      diagnosis: diagnosis.kind,
      strategy: diagnosis.strategy,
      escalation_score: diagnosis.escalation_score,
    });
    try {
      reviveRemotePlayback(reason || "repair");
      reportCallEvent("media_repair_diagnosis", diagnosis);
      if (diagnosis.strategy === "revive_playback") return;
      ensureLocalTracksOnPeerConnection();
      ensureMediaTransceivers();
      if (!isLocalOfferOwner()) {
        if (media.pc.signalingState === "have-remote-offer") {
          await resendLocalSdpAnswer(reason || "media_path_repair");
        } else if (media.pc.signalingState === "have-local-offer") {
          try {
            await media.pc.setLocalDescription({ type: "rollback" });
            reportCallEvent("recipient_offer_rollback", {
              reason: reason || "media_path_repair",
            });
          } catch (_) {
            reportCallEvent("recipient_offer_rollback_failed", {
              reason: reason || "media_path_repair",
            });
          }
        } else {
          reportCallEvent("recipient_repair_waiting_for_offer", {
            reason: reason || "media_path_repair",
            signaling_state: media.pc.signalingState || "",
          });
          setTimeout(() => { backfillLivingPresenceCalls().catch(() => {}); }, 250);
        }
        return;
      }
      await tuneOutboundMediaForTau({
        ...(callUI.lastMetricsSnapshot || {}),
        loss_rate: Math.max(Number(callUI.lastMetricsSnapshot?.loss_rate || 0), 0.09),
        rtt_ms: Math.max(Number(callUI.lastMetricsSnapshot?.rtt_ms || 0), 320),
      });
      if (diagnosis.strategy === "rebuild_peer_connection" || diagnosis.strategy === "relay_rebuild") {
        if (diagnosis.strategy === "relay_rebuild") {
          media.preferRelayNext = true;
          updateOneChip("#call-one-engine", "Relay escape");
          reportCallEvent("relay_escape_requested", {
            reason: reason || "media_path_repair",
            diagnosis: diagnosis.kind,
          });
        }
        const rebuilt = await rebuildPeerConnectionForActiveCall(reason || "media_path_repair");
        if (rebuilt) return;
      }
      if (diagnosis.strategy === "ice_restart" && typeof media.pc.restartIce === "function") {
        media.pc.restartIce();
        reportCallEvent("ice_restart_requested", {
          reason: reason || "watchdog",
          repair_stage: callUI.mediaRepairStage,
          diagnosis: diagnosis.kind,
        });
      }
      if (media.pc.signalingState === "stable") {
        await sendLocalSdpOffer();
      } else if (media.pc.signalingState === "have-local-offer") {
        await resendLocalSdpOffer(reason || "media_path_repair");
      } else if (media.pc.signalingState === "have-remote-offer") {
        await resendLocalSdpAnswer(reason || "media_path_repair");
      }
    } catch (_) {
      reportCallEvent("media_path_repair_failed", { reason: reason || "watchdog" });
    } finally {
      setTimeout(() => {
        if (media.pc && (
          media.pc.iceConnectionState === "connected" ||
          media.pc.iceConnectionState === "completed"
        )) setReconnectState(false);
      }, 2500);
    }
  }

