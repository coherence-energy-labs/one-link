  function stopAllMedia() {
    stopAttestStream();
    if (media.localStream) {
      media.localStream.getTracks().forEach((t) => { try { t.stop(); } catch (_) {} });
      media.localStream = null;
    }
    if (media.remoteStream) {
      // Don't stop tracks (peer owns them), just detach.
      media.remoteStream = null;
    }
    const localV = $$("#call-local-video");
    if (localV) {
      localV.srcObject = null;
      localV.classList.remove("show");
    }
    const remoteV = $$("#call-remote-video");
    if (remoteV) {
      remoteV.srcObject = null;
      remoteV.classList.remove("show");
    }
    const remoteA = $$("#call-remote-audio");
    if (remoteA) remoteA.srcObject = null;
    const surface = $$("#call-active-surface");
    if (surface) surface.classList.remove("has-remote-video");
    if (media.pc) {
      try { media.pc.close(); } catch (_) {}
      media.pc = null;
    }
    media.iceConfigReady = null;
    media.localCandidateAddresses = [];
    media.iceSignalChain = Promise.resolve();
    media.iceHelperReady = false;
    media.iceRelayReady = false;
    media.routePolicy = "direct_first";
    media.forceRelayOnRepair = false;
    media.preferRelayNext = false;
    media.transceiversReady = false;
    callUI.pendingIceCandidates = [];
    callUI.appliedIceKeys.clear();
    callUI.appliedRemoteOfferKeys.clear();
    callUI.appliedRemoteAnswerKeys.clear();
    callUI.localMediaReady = false;
    callUI.lastLocalOfferSdp = "";
    callUI.lastLocalAnswerSdp = "";
    callUI.lastOfferSendMs = 0;
    callUI.lastAnswerSendMs = 0;
    callUI.lastLocalOfferCreatedMs = 0;
    callUI.remoteOfferCollisionCount = 0;
    callUI.lastMetricsSnapshot = null;
    callUI.lastMediaRepairMs = 0;
    callUI.lastInboundVideoBytes = 0;
    callUI.lastInboundAudioBytes = 0;
    callUI.stalledMediaTicks = 0;
    callUI.lastInboundPacketsLost = 0;
    callUI.lastInboundPacketsReceived = 0;
    callUI.qualityEwmaRttMs = null;
    callUI.qualityEwmaLoss = null;
    callUI.qualityBadTicks = 0;
    callUI.qualityGoodTicks = 0;
    callUI.lastUserVisibleRepairMs = 0;
    callUI.adaptationLevel = 0;
    callUI.tauPressureTicks = 0;
    callUI.tauStableTicks = 0;
    callUI.lastTauAdaptMs = 0;
    callUI.tauRiskEwma = null;
    callUI.tauCoherenceEwma = null;
    callUI.tauSurpriseEwma = null;
    callUI.tauBandwidthEwmaKbps = null;
    callUI.tauLastDecision = null;
    callUI.lastCaptureProfile = "";
    callUI.mediaRepairStage = 0;
    callUI.lastPlaybackReviveMs = 0;
    callUI.lastPcRebuildMs = 0;
    callUI.lastRemoteMediaMovingMs = 0;
    callUI.lastRepairDiagnosis = null;
    callUI.repairDiagnosisCounts = {};
    callUI.repairEscalationScore = 0;
    callUI.acceptedCallIds.clear();
    callUI.lastAcceptRetryMs = {};
    media.screenStream = null;
    media.cameraVideoTrack = null;
    media.screenSharing = false;
    media.backgroundBlur = false;
    // doctrine-ok: §3.2.a internal recovery state reset; user copy stays calm.
    media.reconnecting = false;
    media.expectRemoteVideo = false;
    media.expectRemoteAudio = true;
    media.transceiversReady = false;
    media.held = false;
    media.captionsStarting = false;
    _setCaptionsEnabled(false);
    try { media.captionRecognizer?.abort(); } catch (_) {}
    media.captionRecognizer = null;
    const captionsBtn = $$("#btn-call-captions");
    if (captionsBtn) captionsBtn.disabled = false;
    media.layoutMode = "focus";
    media.voiceProcessing = "smart";
    media.muted = false;
    media.cameraOff = false;
    syncMuteCameraButtons();
  }

