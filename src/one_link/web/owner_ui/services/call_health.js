// Isolated service: dependencies are explicit parameters; no owner closure access.
function createCallHealth({
  callUI,
  media,
  setReconnectState,
  updateCallQuality,
  targetMediaProfile,
  applyCaptureProfileForTau,
  updateOneChip,
  addOneCallEvent,
  reportCallEvent,
}) {
  function classifyCallQuality(metrics) {
    const rtt = Number(metrics.smoothed_rtt_ms || metrics.rtt_ms || 0);
    const loss = Number(metrics.loss_rate || 0);
    const ice = String(metrics.ice_connection_state || "");
    const conn = String(metrics.connection_state || "");
    const hasLocal = metrics.has_local_description === true;
    const hasRemote = metrics.has_remote_description === true;
    const health = metrics.media_health || classifyMediaHealth(metrics);
    if (!hasLocal || !hasRemote || ice === "new" || ice === "checking" || conn === "new" || conn === "connecting") {
      return "connecting";
    }
    if (health.state === "signaling_incomplete" || health.state === "remote_media_missing") return "connecting";
    // doctrine-ok: §3.2.a internal state name; user copy says repair/recover.
    if (
      media.reconnecting ||
      health.state === "renderer_detached" ||
      health.state === "playback_frozen" ||
      health.state === "media_starved" ||
      ice === "disconnected" || ice === "failed" ||
      conn === "disconnected" || conn === "failed"
    ) return "reconnecting";
    if (loss >= 0.08 || rtt >= 450) return "bad";
    if (loss >= 0.025 || rtt >= 180) return "fair";
    return "good";
  }

  function applyCallQualityHysteresis(rawLevel, label) {
    if (rawLevel === "connecting") {
      callUI.qualityGoodTicks = 0;
      setReconnectState(false);
      updateCallQuality("connecting", label || "Connecting media");
      return;
    }
    // doctrine-ok: §3.2.a internal state name; user copy says repair/recover.
    if (rawLevel === "reconnecting" || rawLevel === "bad") {
      callUI.qualityBadTicks += 1;
      callUI.qualityGoodTicks = 0;
    } else if (rawLevel === "good") {
      callUI.qualityGoodTicks += 1;
      callUI.qualityBadTicks = Math.max(0, callUI.qualityBadTicks - 1);
    } else {
      callUI.qualityGoodTicks = 0;
      callUI.qualityBadTicks = Math.max(0, callUI.qualityBadTicks - 1);
    }
    const showProblem = callUI.qualityBadTicks >= 3;
    const clearProblem = callUI.qualityGoodTicks >= 2;
    if (showProblem) {
      // doctrine-ok: §3.2.a internal state name; visible copy says repair/recover.
      setReconnectState(rawLevel === "reconnecting", label || (
        rawLevel === "reconnecting" ? "Repairing media path..." : "Call quality is recovering..."
      ));
      updateCallQuality(rawLevel, label);
      return;
    }
    if (clearProblem || rawLevel === "good") {
      setReconnectState(false);
      updateCallQuality(rawLevel === "fair" ? "fair" : "good", label);
      return;
    }
    updateCallQuality(rawLevel === "fair" ? "fair" : "good", label);
  }

  function expectedRemoteMediaMissing(selected) {
    if (!selected || !selected.has_remote_description) return false;
    const missingAudio = media.expectRemoteAudio
      && selected.remote_live_audio_tracks === 0
      && selected.inbound_audio_packets === 0;
    const missingVideo = media.expectRemoteVideo
      && (
        selected.remote_live_video_tracks === 0
        || (
          selected.remote_video_element_shown !== true
          && selected.remote_video_width === 0
          && selected.inbound_video_frames_decoded === 0
        )
        || (
          selected.remote_muted_video_tracks >= selected.remote_live_video_tracks
          && selected.inbound_video_packets === 0
        )
      );
    return missingAudio || missingVideo;
  }

  function classifyMediaHealth(metrics) {
    const selected = metrics || {};
    const ice = String(selected.ice_connection_state || "");
    const conn = String(selected.connection_state || "");
    const signaling = String(selected.signaling_state || "");
    const hasLocal = selected.has_local_description === true;
    const hasRemote = selected.has_remote_description === true;
    const remoteMissing = expectedRemoteMediaMissing(selected);
    const expectsVideo = media.expectRemoteVideo === true;
    const expectsAudio = media.expectRemoteAudio === true;
    const videoTracks = Number(selected.remote_video_tracks || 0);
    const audioTracks = Number(selected.remote_audio_tracks || 0);
    const inboundVideoPackets = Number(selected.inbound_video_packets || 0);
    const inboundAudioPackets = Number(selected.inbound_audio_packets || 0);
    const inboundVideoFramesDecoded = Number(selected.inbound_video_frames_decoded || 0);
    const remoteVideoWidth = Number(selected.remote_video_width || 0);
    const remoteVideoReady = Number(selected.remote_video_ready_state || 0);
    const rendererDetached = (
      (videoTracks > 0 && selected.remote_video_src_attached === false) ||
      (audioTracks > 0 && selected.remote_audio_src_attached === false)
    );
    const rendererHidden = expectsVideo
      && videoTracks > 0
      && selected.remote_video_element_shown !== true
      && remoteVideoWidth === 0;
    const secondsSinceMoving = callUI.lastRemoteMediaMovingMs
      ? Math.round((Date.now() - Number(callUI.lastRemoteMediaMovingMs || 0)) / 1000)
      : null;
    const playbackFrozen = Number(callUI.frozenMediaTicks || 0) > 0
      || (remoteVideoReady >= 2 && inboundVideoPackets > 0 && secondsSinceMoving !== null && secondsSinceMoving >= 6);
    const mediaStarved = (expectsAudio || expectsVideo)
      && inboundVideoPackets === 0
      && inboundAudioPackets === 0
      && secondsSinceMoving !== null
      && secondsSinceMoving >= 8;
    const noVideoFrames = expectsVideo
      && videoTracks > 0
      && inboundVideoFramesDecoded === 0
      && remoteVideoWidth === 0;
    let state = "healthy";
    let strategy = "none";
    let severity = 0;
    if (!hasLocal || !hasRemote || signaling === "have-local-offer" || signaling === "have-remote-offer") {
      state = "signaling_incomplete";
      strategy = "resend_sdp";
      severity = 2;
    } else if (ice === "failed" || conn === "failed") {
      state = "ice_failed";
      strategy = "ice_restart";
      severity = 3;
    } else if (ice === "disconnected" || conn === "disconnected" || ice === "checking") {
      state = "ice_unstable";
      strategy = "ice_restart";
      severity = 2;
    } else if (remoteMissing) {
      state = "remote_media_missing";
      strategy = "renegotiate";
      severity = 2;
    } else if (rendererDetached || rendererHidden) {
      state = "renderer_detached";
      strategy = "revive_playback";
      severity = 1;
    } else if (playbackFrozen || noVideoFrames) {
      state = "playback_frozen";
      strategy = "revive_playback";
      severity = 1;
    } else if (mediaStarved) {
      state = "media_starved";
      strategy = "renegotiate";
      severity = 2;
    }
    return {
      state,
      strategy,
      severity,
      remote_missing: remoteMissing,
      renderer_detached: rendererDetached,
      renderer_hidden: rendererHidden,
      playback_frozen: playbackFrozen,
      media_starved: mediaStarved,
      no_video_frames: noVideoFrames,
      seconds_since_media_moving: secondsSinceMoving,
    };
  }

  function selectedCandidatePairFromStats(stats, statById) {
    let selectedPair = null;
    stats.forEach((s) => {
      if (s.type === "transport" && s.selectedCandidatePairId && statById.has(s.selectedCandidatePairId)) {
        selectedPair = statById.get(s.selectedCandidatePairId);
      }
    });
    if (selectedPair) return selectedPair;
    stats.forEach((s) => {
      if (selectedPair) return;
      if (s.type === "candidate-pair" && (s.selected === true || s.nominated === true || s.state === "succeeded")) {
        selectedPair = s;
      }
    });
    return selectedPair;
  }

  function clampUnit(value) {
    const n = Number(value);
    if (!Number.isFinite(n)) return 0;
    return Math.max(0, Math.min(1, n));
  }

  function ewmaNullable(previous, value, alpha) {
    const n = Number(value);
    if (!Number.isFinite(n)) return previous;
    return previous == null ? n : (Number(previous) * (1 - alpha)) + (n * alpha);
  }

  function scoreMediaPathForTau(metrics) {
    const currentLevel = Math.max(0, Math.min(3, Number(callUI.adaptationLevel || 0)));
    const profile = targetMediaProfile(currentLevel) || targetMediaProfile(0);
    const rtt = Number(metrics.smoothed_rtt_ms || metrics.rtt_ms || 0);
    const loss = Number(metrics.loss_rate || metrics.raw_loss_rate || 0);
    const jitter = Number(metrics.jitter_ms || 0);
    const bandwidthKbps = Number(metrics.bandwidth_estimate_kbps || 0);
    if (bandwidthKbps > 0) {
      callUI.tauBandwidthEwmaKbps = ewmaNullable(callUI.tauBandwidthEwmaKbps, bandwidthKbps, 0.22);
    }
    const smoothedBandwidthKbps = Number(callUI.tauBandwidthEwmaKbps || bandwidthKbps || 0);
    const expectedKbps = profile ? Math.max(1, Number(profile.maxBitrate || 0) / 1000) : 850;
    const health = metrics.media_health || classifyMediaHealth(metrics);
    const remoteWaiting = health.state === "remote_media_missing";
    const ice = String(metrics.ice_connection_state || "");
    const conn = String(metrics.connection_state || "");
    const route = String(metrics.selected_candidate_type || "");
    const icePenalty = (ice === "failed" || conn === "failed") ? 1
      : (ice === "disconnected" || conn === "disconnected") ? 0.82
      : (ice === "checking" || conn === "connecting" || ice === "new") ? 0.46
      : 0;
    const routePenalty = route === "relay" ? 0.10 : route === "srflx" || route === "prflx" ? 0.04 : 0;
    const bandwidthPressure = smoothedBandwidthKbps > 0
      ? clampUnit((expectedKbps - smoothedBandwidthKbps * 0.72) / expectedKbps)
      : 0.18;
    const healthPressure = clampUnit(Number(health.severity || 0) / 3);
    const freezePressure = Math.max(
      remoteWaiting ? 1 : 0,
      healthPressure,
      clampUnit(Number(callUI.frozenMediaTicks || 0) / 3),
    );
    const stallPressure = clampUnit(Number(callUI.stalledMediaTicks || 0) / 4);
    const rttPressure = clampUnit((rtt - 70) / 560);
    const lossPressure = clampUnit(loss / 0.16);
    const jitterPressure = clampUnit(jitter / 170);
    const rawRisk = clampUnit(
      (0.28 * lossPressure) +
      (0.21 * rttPressure) +
      (0.16 * jitterPressure) +
      (0.16 * freezePressure) +
      (0.08 * stallPressure) +
      (0.07 * bandwidthPressure) +
      (0.08 * icePenalty) +
      routePenalty
    );
    callUI.tauRiskEwma = ewmaNullable(
      callUI.tauRiskEwma,
      rawRisk,
      rawRisk > Number(callUI.tauRiskEwma || 0) ? 0.38 : 0.16,
    );
    const risk = clampUnit(callUI.tauRiskEwma);
    const coherence = clampUnit(1 - risk);
    callUI.tauCoherenceEwma = ewmaNullable(callUI.tauCoherenceEwma, coherence, 0.2);
    const surprise = -Math.log(Math.max(0.01, Number(callUI.tauCoherenceEwma || coherence || 0.01)));
    callUI.tauSurpriseEwma = ewmaNullable(callUI.tauSurpriseEwma, surprise, 0.2);
    return {
      rawRisk,
      risk,
      coherence: clampUnit(callUI.tauCoherenceEwma),
      surprise: Number(callUI.tauSurpriseEwma || surprise || 0),
      rttPressure,
      lossPressure,
      jitterPressure,
      freezePressure,
      stallPressure,
      bandwidthPressure,
      icePenalty,
      routePenalty,
      bandwidthKbps: smoothedBandwidthKbps,
      expectedKbps,
      remoteWaiting,
    };
  }

  function chooseTauVideoLevel(metrics) {
    const score = scoreMediaPathForTau(metrics);
    const currentLevel = Math.max(0, Math.min(3, Number(callUI.adaptationLevel || 0)));
    let targetLevel = currentLevel;
    const critical = score.risk >= 0.78 || score.icePenalty >= 1 || score.freezePressure >= 1;
    const pressured = score.risk >= 0.52 || score.bandwidthPressure >= 0.72 || score.lossPressure >= 0.62;
    const cautious = score.risk >= 0.30 || score.jitterPressure >= 0.46;
    const excellent = score.risk <= 0.14 && score.coherence >= 0.82 && !score.remoteWaiting && score.icePenalty === 0;
    if (critical) {
      callUI.tauPressureTicks += 2;
      callUI.tauStableTicks = 0;
    } else if (pressured) {
      callUI.tauPressureTicks += 1;
      callUI.tauStableTicks = 0;
    } else if (excellent) {
      callUI.tauStableTicks += 1;
      callUI.tauPressureTicks = Math.max(0, callUI.tauPressureTicks - 1);
    } else if (cautious) {
      callUI.tauPressureTicks = Math.max(1, callUI.tauPressureTicks);
      callUI.tauStableTicks = 0;
    } else {
      callUI.tauPressureTicks = Math.max(0, callUI.tauPressureTicks - 1);
      callUI.tauStableTicks = Math.max(0, callUI.tauStableTicks - 1);
    }
    if (critical && callUI.tauPressureTicks >= 2) targetLevel = 3;
    else if (pressured && callUI.tauPressureTicks >= 2) targetLevel = Math.max(currentLevel, Math.min(2, currentLevel + 1));
    else if (cautious && callUI.tauPressureTicks >= 3) targetLevel = Math.max(currentLevel, 1);
    else if (excellent && callUI.tauStableTicks >= 5) targetLevel = Math.max(0, currentLevel - 1);
    return {
      ...score,
      currentLevel,
      targetLevel,
      reason: critical ? "critical_path_risk"
        : pressured ? "path_pressure"
        : cautious ? "path_caution"
        : excellent ? "stable_recovery"
        : "hold",
    };
  }

  async function tuneOutboundMediaForTau(metrics) {
    if (!media.pc || !media.pc.getSenders) return;
    const decision = chooseTauVideoLevel(metrics);
    callUI.tauLastDecision = decision;
    // doctrine-ok: §3.2.a internal state name; no user-facing reconnect prompt.
    const cooldownMs = decision.targetLevel > decision.currentLevel ? 2800 : 9000;
    const now = Date.now();
    if (now - Number(callUI.lastTauAdaptMs || 0) < cooldownMs) return;
    const targetLevel = decision.targetLevel;
    if (targetLevel === callUI.adaptationLevel) return;
    callUI.adaptationLevel = targetLevel;
    callUI.lastTauAdaptMs = now;
    const caps = targetMediaProfile(targetLevel);
    await applyCaptureProfileForTau(targetLevel, decision.reason);
    for (const sender of media.pc.getSenders()) {
      if (!sender || !sender.track || sender.track.kind !== "video" || !sender.getParameters) continue;
      try {
        const params = sender.getParameters();
        params.encodings = params.encodings && params.encodings.length ? params.encodings : [{}];
        params.encodings[0].maxBitrate = caps.maxBitrate;
        params.encodings[0].scaleResolutionDownBy = caps.scale;
        params.degradationPreference = targetLevel >= 2 ? "maintain-framerate" : "balanced";
        if (sender.setParameters) await sender.setParameters(params);
      } catch (_) {}
    }
    updateOneChip("#call-one-engine", targetLevel === 0 ? "Tau full" : targetLevel === 1 ? "Tau steady" : targetLevel === 2 ? "Tau voice-first" : "Tau audio-first");
    addOneCallEvent(targetLevel === 0
      ? "Tau restored full video quality."
      : "Tau lowered video load to keep the call stable.");
    reportCallEvent("tau_media_adapted", {
      state: targetLevel === 0 ? "full" : targetLevel === 1 ? "steady" : "survival",
      reason: decision.reason,
      risk: Math.round(decision.risk * 1000) / 1000,
      coherence: Math.round(decision.coherence * 1000) / 1000,
      surprise: Math.round(decision.surprise * 1000) / 1000,
      bandwidth_pressure: Math.round(decision.bandwidthPressure * 1000) / 1000,
      loss_pressure: Math.round(decision.lossPressure * 1000) / 1000,
      rtt_pressure: Math.round(decision.rttPressure * 1000) / 1000,
    });
  }

  return {
    classifyCallQuality,
    applyCallQualityHysteresis,
    expectedRemoteMediaMissing,
    classifyMediaHealth,
    selectedCandidatePairFromStats,
    clampUnit,
    ewmaNullable,
    scoreMediaPathForTau,
    chooseTauVideoLevel,
    tuneOutboundMediaForTau,
  };
}
