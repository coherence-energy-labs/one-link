  async function reportCallMetricsOnce() {
    if (!callUI.activeCallId || !media.pc) return;
    try {
      const stats = await media.pc.getStats();
      let rttMs = null;
      let jitterMs = null;
      let loss = null;
      let kbps = null;
      let inboundAudioBytes = 0;
      let inboundAudioPackets = 0;
      let inboundVideoBytes = 0;
      let inboundVideoPackets = 0;
      let inboundVideoFramesDecoded = 0;
      let inboundVideoFramesDropped = 0;
      let inboundPacketsLost = 0;
      let inboundPacketsReceived = 0;
      const statById = new Map();
      stats.forEach((s) => { if (s && s.id) statById.set(s.id, s); });
      let selectedCandidateType = "";
      let selectedCandidateProtocol = "";
      let selectedCandidateNetwork = "";
      const selectedPair = selectedCandidatePairFromStats(stats, statById);
      if (selectedPair) {
        if (typeof selectedPair.currentRoundTripTime === "number") {
          rttMs = Math.round(selectedPair.currentRoundTripTime * 1000);
        }
        const bytes = Number(selectedPair.availableOutgoingBitrate || 0);
        if (bytes > 0) kbps = Math.round(bytes / 1000);
        const localCand = statById.get(selectedPair.localCandidateId);
        if (localCand) {
          selectedCandidateType = String(localCand.candidateType || "");
          selectedCandidateProtocol = String(localCand.protocol || "");
          selectedCandidateNetwork = String(localCand.networkType || "");
        }
      }
      stats.forEach((s) => {
        if (s.type === "candidate-pair" && (s.selected || s.nominated)) {
          if (rttMs === null && typeof s.currentRoundTripTime === "number") {
            rttMs = Math.round(s.currentRoundTripTime * 1000);
          }
          const bytes = Number(s.availableOutgoingBitrate || 0);
          if (kbps === null && bytes > 0) kbps = Math.round(bytes / 1000);
          const localCand = statById.get(s.localCandidateId);
          if (!selectedCandidateType && localCand) {
            selectedCandidateType = String(localCand.candidateType || "");
            selectedCandidateProtocol = String(localCand.protocol || "");
            selectedCandidateNetwork = String(localCand.networkType || "");
          }
        }
        if (s.type === "inbound-rtp" && !s.isRemote) {
          if (typeof s.jitter === "number") jitterMs = Math.round(s.jitter * 1000);
          const lost = Number(s.packetsLost || 0);
          const received = Number(s.packetsReceived || 0);
          inboundPacketsLost += lost;
          inboundPacketsReceived += received;
        }
        if (s.type === "inbound-rtp" && !s.isRemote) {
          const kind = String(s.kind || s.mediaType || "").toLowerCase();
          if (kind === "audio") {
            inboundAudioBytes += Number(s.bytesReceived || 0);
            inboundAudioPackets += Number(s.packetsReceived || 0);
          } else if (kind === "video") {
            inboundVideoBytes += Number(s.bytesReceived || 0);
            inboundVideoPackets += Number(s.packetsReceived || 0);
            inboundVideoFramesDecoded += Number(s.framesDecoded || 0);
            inboundVideoFramesDropped += Number(s.framesDropped || 0);
          }
        }
      });
      if (inboundPacketsLost + inboundPacketsReceived > 0) {
        const deltaLost = Math.max(0, inboundPacketsLost - Number(callUI.lastInboundPacketsLost || 0));
        const deltaReceived = Math.max(0, inboundPacketsReceived - Number(callUI.lastInboundPacketsReceived || 0));
        if (deltaLost + deltaReceived > 0) {
          loss = deltaLost / (deltaLost + deltaReceived);
        } else {
          loss = inboundPacketsLost / (inboundPacketsLost + inboundPacketsReceived);
        }
        callState.update({
          lastInboundPacketsLost: inboundPacketsLost,
          lastInboundPacketsReceived: inboundPacketsReceived,
        });
      }
      if (rttMs !== null) {
        callState.set("qualityEwmaRttMs", callUI.qualityEwmaRttMs === null
          ? rttMs
          : Math.round((callUI.qualityEwmaRttMs * 0.7) + (rttMs * 0.3)));
      }
      if (loss !== null) {
        callState.set("qualityEwmaLoss", callUI.qualityEwmaLoss === null
          ? loss
          : (callUI.qualityEwmaLoss * 0.75) + (loss * 0.25));
      }
      if (rttMs !== null) updateOneChip("#call-one-rtt", `${rttMs} ms`);
      if (loss !== null) updateOneChip("#call-one-loss", `${Math.round(loss * 100)}%`);
      if (kbps !== null) updateOneChip("#call-one-route", kbps > 5000 ? "Fast local" : "Local");
      const selected = {
        ice_connection_state: media.pc.iceConnectionState || null,
        connection_state: media.pc.connectionState || null,
        ice_gathering_state: media.pc.iceGatheringState || null,
        signaling_state: media.pc.signalingState || null,
        has_local_description: !!media.pc.localDescription,
        has_remote_description: !!media.pc.remoteDescription,
        local_audio_tracks: media.localStream ? media.localStream.getAudioTracks().length : 0,
        local_video_tracks: media.localStream ? media.localStream.getVideoTracks().length : 0,
        local_live_audio_tracks: media.localStream ? media.localStream.getAudioTracks().filter((t) => t.readyState === "live").length : 0,
        local_live_video_tracks: media.localStream ? media.localStream.getVideoTracks().filter((t) => t.readyState === "live").length : 0,
        remote_audio_tracks: media.remoteStream ? media.remoteStream.getAudioTracks().length : 0,
        remote_video_tracks: media.remoteStream ? media.remoteStream.getVideoTracks().length : 0,
        remote_live_audio_tracks: media.remoteStream ? media.remoteStream.getAudioTracks().filter((t) => t.readyState === "live").length : 0,
        remote_live_video_tracks: media.remoteStream ? media.remoteStream.getVideoTracks().filter((t) => t.readyState === "live").length : 0,
        remote_muted_audio_tracks: media.remoteStream ? media.remoteStream.getAudioTracks().filter((t) => t.muted).length : 0,
        remote_muted_video_tracks: media.remoteStream ? media.remoteStream.getVideoTracks().filter((t) => t.muted).length : 0,
        inbound_audio_bytes: inboundAudioBytes,
        inbound_audio_packets: inboundAudioPackets,
        inbound_video_bytes: inboundVideoBytes,
        inbound_video_packets: inboundVideoPackets,
        inbound_video_frames_decoded: inboundVideoFramesDecoded,
        inbound_video_frames_dropped: inboundVideoFramesDropped,
        remote_video_width: Number($$("#call-remote-video")?.videoWidth || 0),
        remote_video_height: Number($$("#call-remote-video")?.videoHeight || 0),
        remote_video_ready_state: Number($$("#call-remote-video")?.readyState || 0),
        remote_video_paused: $$("#call-remote-video")?.paused === true,
        remote_video_element_shown: $$("#call-remote-video")?.classList.contains("show") === true,
        remote_video_src_attached: !!($$("#call-remote-video") && media.remoteStream && $$("#call-remote-video").srcObject === media.remoteStream),
        remote_audio_src_attached: !!($$("#call-remote-audio") && media.remoteStream && $$("#call-remote-audio").srcObject === media.remoteStream),
        selected_candidate_type: selectedCandidateType,
        selected_candidate_protocol: selectedCandidateProtocol,
        selected_candidate_network: selectedCandidateNetwork,
        ice_helper_ready: media.iceHelperReady === true,
        ice_relay_ready: media.iceRelayReady === true,
        route_policy: media.routePolicy,
        relay_escape_active: media.preferRelayNext === true,
        best_relay_health: media.bestRelayHealth || null,
        best_relay_score: media.bestRelayScore,
      };
      if (selectedCandidateType === "relay") updateOneChip("#call-one-route", "Relay");
      else if (selectedCandidateType === "srflx" || selectedCandidateType === "prflx") updateOneChip("#call-one-route", "Assisted");
      else if (selectedCandidateType === "host") updateOneChip("#call-one-route", "Direct");
      if (!media.iceRelayReady && selected.has_remote_description && selected.ice_connection_state === "checking") {
        updateOneChip("#call-one-engine", "Direct only");
      }
      const surfaceState = syncRemoteMediaSurface("metrics");
      selected.remote_video_element_shown = surfaceState.hasRenderableVideo;
      selected.remote_video_src_attached = !!(surfaceState.videoEl && surfaceState.stream && surfaceState.videoEl.srcObject === surfaceState.stream);
      selected.remote_audio_src_attached = !!(surfaceState.audioEl && surfaceState.stream && surfaceState.audioEl.srcObject === surfaceState.stream);
      const mediaHealth = classifyMediaHealth(selected);
      selected.media_health_state = mediaHealth.state;
      selected.media_health_strategy = mediaHealth.strategy;
      selected.media_health_severity = mediaHealth.severity;
      selected.media_health_renderer_detached = mediaHealth.renderer_detached;
      selected.media_health_renderer_hidden = mediaHealth.renderer_hidden;
      selected.media_health_no_video_frames = mediaHealth.no_video_frames;
      callState.set("lastMetricsSnapshot", {
        at_ms: Date.now(),
        ...selected,
        media_health: mediaHealth,
        rtt_ms: rttMs,
        jitter_ms: jitterMs,
        loss_rate: callUI.qualityEwmaLoss === null ? loss : callUI.qualityEwmaLoss,
        raw_loss_rate: loss,
        raw_rtt_ms: rttMs,
        smoothed_rtt_ms: callUI.qualityEwmaRttMs,
        bandwidth_estimate_kbps: kbps,
        remote_tracks: remoteTrackSummary(),
      });
      const quality = classifyCallQuality(callUI.lastMetricsSnapshot);
      applyCallQualityHysteresis(quality);
      renderParticipants();
      renderLiveStats(callUI.lastMetricsSnapshot);
      if (
        media.iceRelayReady
        && (
          selected.ice_connection_state === "checking"
          || selected.ice_connection_state === "disconnected"
          || selected.media_health_severity >= 2
        )
      ) {
        requestRelayHealthProbe("metrics").catch(() => {});
      }
      maybeRefreshTurnCredentials("metrics");
      tuneOutboundMediaForTau(callUI.lastMetricsSnapshot).catch(() => {});
      const videoMoving = inboundVideoBytes > Number(callUI.lastInboundVideoBytes || 0)
        || inboundVideoFramesDecoded > Number(callUI.lastInboundVideoFramesDecoded || 0);
      const audioMoving = inboundAudioBytes > Number(callUI.lastInboundAudioBytes || 0);
      const remoteVideoEl = $$("#call-remote-video");
      const remoteAudioEl = $$("#call-remote-audio");
      const remoteVideoTime = Number(remoteVideoEl?.currentTime || 0);
      const remoteAudioTime = Number(remoteAudioEl?.currentTime || 0);
      const videoElementMoving = remoteVideoTime > Number(callUI.lastRemoteVideoTime || 0);
      const audioElementMoving = remoteAudioTime > Number(callUI.lastRemoteAudioTime || 0);
      const videoElementFrozen = selected.remote_video_tracks > 0
        && selected.remote_video_width > 0
        && selected.remote_video_ready_state >= 2
        && !videoElementMoving
        && !videoMoving;
      const audioElementFrozen = selected.remote_audio_tracks > 0
        && !audioElementMoving
        && !audioMoving;
      callState.update({
        lastRemoteVideoTime: remoteVideoTime,
        lastRemoteAudioTime: remoteAudioTime,
        lastInboundVideoBytes: inboundVideoBytes,
        lastInboundAudioBytes: inboundAudioBytes,
        lastInboundVideoFramesDecoded: inboundVideoFramesDecoded,
      });
      if (videoMoving || audioMoving || videoElementMoving || audioElementMoving) {
        callState.update({
          lastRemoteMediaMovingMs: Date.now(),
          frozenMediaTicks: 0,
        });
        if (
          selected.ice_connection_state === "connected" ||
          selected.ice_connection_state === "completed"
        ) {
          callState.set("mediaRepairStage", 0);
          markMediaRepairHealthy();
        }
      }
      if (
        selected.has_remote_description
        && (selected.remote_video_tracks > 0 || selected.remote_audio_tracks > 0)
        && selected.ice_connection_state !== "connected"
        && selected.ice_connection_state !== "completed"
      ) {
        callState.increment("stalledMediaTicks", 1);
      } else if (mediaHealth.state === "remote_media_missing" || mediaHealth.state === "media_starved") {
        callState.increment("stalledMediaTicks", 1);
      } else if (mediaHealth.state === "renderer_detached") {
        reviveRemotePlayback("renderer_detached");
        callState.increment("stalledMediaTicks", 1);
      } else if (selected.remote_video_tracks > 0 && !videoMoving && selected.inbound_video_packets > 0) {
        callState.increment("stalledMediaTicks", 1);
      } else if (selected.remote_audio_tracks > 0 && !audioMoving && selected.inbound_audio_packets > 0) {
        callState.increment("stalledMediaTicks", 1);
      } else {
        callState.set("stalledMediaTicks", 0);
      }
      if (videoElementFrozen || audioElementFrozen) {
        callState.increment("frozenMediaTicks", 1);
      } else {
        callState.set("frozenMediaTicks", 0);
      }
      if (callUI.stalledMediaTicks >= 3) {
        callState.set("stalledMediaTicks", 0);
        repairMediaPath("stalled_media").catch(() => {});
      }
      if (callUI.frozenMediaTicks >= 3) {
        callState.set("frozenMediaTicks", 0);
        reportCallEvent("remote_media_frozen", {
          video_frozen: videoElementFrozen,
          audio_frozen: audioElementFrozen,
        });
        captureAutoCallTrace("sustained_media_freeze", {
          video_frozen: videoElementFrozen,
          audio_frozen: audioElementFrozen,
          media_health_state: selected.media_health_state,
          ice_connection_state: selected.ice_connection_state,
        }).catch(() => {});
        repairMediaPath("frozen_media").catch(() => {});
      }
      if (
        selected.remote_video_tracks > 0
        && selected.inbound_video_frames_decoded === 0
        && selected.remote_video_width === 0
      ) {
        const now = Date.now();
        if (now - callUI.lastFrameWarningMs > 5000) {
          callState.set("lastFrameWarningMs", now);
          reportCallEvent("remote_video_no_frames", { media_kind: "video" });
        }
      }
      ensureMediaNegotiation("metrics").catch(() => {});
      const metricsResult = await callApiPost({
        action: "report_metrics",
        call_id: callUI.activeCallId,
        rtt_ms: rttMs,
        jitter_ms: jitterMs,
        loss_rate: loss,
        bandwidth_estimate_kbps: kbps,
        tau_risk: callUI.tauLastDecision ? callUI.tauLastDecision.risk : null,
        tau_coherence: callUI.tauLastDecision ? callUI.tauLastDecision.coherence : null,
        tau_level: callUI.adaptationLevel,
        ...selected,
      });
      await applyBackendPathRecommendation(
        metricsResult && metricsResult.recommendation,
        callUI.lastMetricsSnapshot,
      );
      await applyBackendRecoveryIntent(
        metricsResult && metricsResult.recovery_intent,
        callUI.lastMetricsSnapshot,
      );
      if (metricsResult && metricsResult.routePolicy) mediaState.recordRoutePolicy(metricsResult.routePolicy);
      applyBackendSessionAuthority(
        metricsResult && metricsResult.session_authority,
      );
    } catch (_) {}
  }

  if (typeof window !== "undefined") {
    window._oneLinkCallDebug = async function () {
      let statsSummary = [];
      try {
        if (media.pc) {
          const stats = await media.pc.getStats();
          stats.forEach((s) => {
            if (s.type === "inbound-rtp" || s.type === "outbound-rtp" || s.type === "candidate-pair") {
              statsSummary.push({
                type: s.type,
                kind: s.kind || s.mediaType || "",
                selected: s.selected === true || s.nominated === true,
                state: s.state || "",
                bytesReceived: Number(s.bytesReceived || 0),
                bytesSent: Number(s.bytesSent || 0),
                packetsReceived: Number(s.packetsReceived || 0),
                packetsSent: Number(s.packetsSent || 0),
                framesDecoded: Number(s.framesDecoded || 0),
                framesEncoded: Number(s.framesEncoded || 0),
              });
            }
          });
        }
      } catch (_) {
        statsSummary = [{ error: "stats_unavailable" }];
      }
      const rv = $$("#call-remote-video");
      const ra = $$("#call-remote-audio");
      return {
        call_id: callUI.activeCallId,
        peer: callUI.activeCallPeer,
        pc: media.pc ? {
          signalingState: media.pc.signalingState,
          iceConnectionState: media.pc.iceConnectionState,
          connectionState: media.pc.connectionState,
          iceGatheringState: media.pc.iceGatheringState,
          localDescriptionType: media.pc.localDescription && media.pc.localDescription.type,
          remoteDescriptionType: media.pc.remoteDescription && media.pc.remoteDescription.type,
        } : null,
        local_tracks: media.localStream ? media.localStream.getTracks().map((t) => ({
          kind: t.kind, readyState: t.readyState, muted: t.muted === true, enabled: t.enabled !== false,
        })) : [],
        remote_tracks: remoteTrackSummary(),
        remote_video_element: rv ? {
          shown: rv.classList.contains("show"),
          srcAttached: !!(media.remoteStream && rv.srcObject === media.remoteStream),
          videoWidth: rv.videoWidth,
          videoHeight: rv.videoHeight,
          readyState: rv.readyState,
          paused: rv.paused,
          ended: rv.ended,
          currentTime: rv.currentTime,
        } : null,
        remote_audio_element: ra ? {
          srcAttached: !!(media.remoteStream && ra.srcObject === media.remoteStream),
          readyState: ra.readyState,
          paused: ra.paused,
          ended: ra.ended,
          currentTime: ra.currentTime,
        } : null,
        last_metrics: callUI.lastMetricsSnapshot,
        tau_decision: callUI.tauLastDecision,
        backend_recommendation: callUI.lastBackendRecommendation,
        recovery_intent: callUI.lastRecoveryIntent,
        session_authority: callUI.lastSessionAuthority,
        backend_action_cooldowns: callUI.backendActionCooldowns,
        auto_trace_buffer: callUI.autoTraceBuffer,
        repair_diagnosis: callUI.lastRepairDiagnosis,
        repair_counts: callUI.repairDiagnosisCounts,
        repair_escalation_score: callUI.repairEscalationScore,
        stats: statsSummary,
      };
    };
  }

  function startCallTelemetry() {
    if (callUI.metricsTimer) clearInterval(callUI.metricsTimer);
    reportCallMetricsOnce();
    callState.set("metricsTimer", setInterval(reportCallMetricsOnce, 2000));
    startMediaWatchdog();
  }

  function stopCallTelemetry() {
    if (callUI.metricsTimer) {
      clearInterval(callUI.metricsTimer);
      callState.set("metricsTimer", null);
    }
    stopMediaWatchdog();
  }

  function startMediaWatchdog() {
    if (callUI.mediaWatchdogTimer) clearInterval(callUI.mediaWatchdogTimer);
    callState.set("mediaWatchdogTimer", setInterval(() => {
      syncRemoteMediaSurface("watchdog");
      ensureMediaNegotiation("watchdog");
      if (
        callUI.activeCallId &&
        media.pc &&
        media.pc.remoteDescription &&
        Date.now() - Number(callUI.lastRemoteMediaMovingMs || 0) > 8000
      ) {
        captureAutoCallTrace("watchdog_no_media_movement", {
          seconds_since_media_moved: Math.round((Date.now() - Number(callUI.lastRemoteMediaMovingMs || 0)) / 1000),
          ice_connection_state: media.pc.iceConnectionState || "",
          connection_state: media.pc.connectionState || "",
          signaling_state: media.pc.signalingState || "",
        }).catch(() => {});
        repairMediaPath("watchdog_no_media_movement").catch(() => {});
      }
    }, 1500));
  }

  function stopMediaWatchdog() {
    if (callUI.mediaWatchdogTimer) {
      clearInterval(callUI.mediaWatchdogTimer);
      callState.set("mediaWatchdogTimer", null);
    }
  }

  if (window.addEventListener) {
    window.addEventListener("online", () => {
      const now = Date.now();
      if (!callUI.activeCallId || now - Number(callUI.lastNetworkResumeRepairMs || 0) < 3000) return;
      callState.set("lastNetworkResumeRepairMs", now);
      reportCallEvent("network_resume_repair");
      repairMediaPath("network_online").catch(() => {});
    });

    window.addEventListener("offline", () => {
      if (!callUI.activeCallId) return;
      setReconnectState(true, "Network paused. Holding the call...");
      reportCallEvent("network_offline");
    });
  }

