  // ── Button handlers ──
  const cancelBtn = $$("#btn-call-cancel");
  if (cancelBtn) cancelBtn.addEventListener("click", async () => {
    if (!callUI.activeCallId) return;
    const callId = callUI.activeCallId;
    hideOutgoingOverlay();
    callUI.activeCallId = null;
    callUI.activeCallLocalRole = "";
    await callApiPost({ action: "hangup", call_id: callId });
  });
  const declineBtn = $$("#btn-call-decline");
  if (declineBtn) declineBtn.addEventListener("click", async () => {
    if (!callUI.inboundCallId) return;
    const callId = callUI.inboundCallId;
    hideIncomingRing();
    callUI.inboundCallId = null;
    await callApiPost({ action: "decline", call_id: callId });
  });
  const acceptBtn = $$("#btn-call-accept");
  if (acceptBtn) acceptBtn.addEventListener("click", async () => {
    await acceptInboundCall();
    return;
    if (!callUI.inboundCallId) return;
    const result = await callApiPost({
      action: "accept", call_id: callUI.inboundCallId,
    });
    hideIncomingRing();
    if (result.ok) {
      callUI.activeCallId = callUI.inboundCallId;
      callUI.activeCallPeer = callUI.inboundCallPeer;
      callUI.activeCallPeerFp = callUI.inboundCallPeerFp;
      showActiveSurface(callUI.activeCallPeer, "");
      // Tier α: bring up local media on accept.
      setupRtcPeerConnection();
      const stream = await startLocalMedia({ audio: true, video: true });
      if (stream && media.pc) {
        stream.getTracks().forEach((t) => {
          try { media.pc.addTrack(t, stream); } catch (_) {}
        });
        // Tier β - start per-window frame attestation.
        startAttestStream(stream);
      }
      // If the originator's SDP offer arrived before we accepted,
      // it's been parked in pendingRemoteOffer. Apply it now and
      // emit our answer.
      if (callUI.pendingRemoteOffer) {
        const offerSdp = callUI.pendingRemoteOffer;
        callUI.pendingRemoteOffer = null;
        await applyRemoteSdpOffer(offerSdp);
      }
    }
    callUI.inboundCallId = null;
    callUI.inboundCallPeerFp = null;
  });
  const hangupBtn = $$("#btn-call-hangup");
  if (hangupBtn) hangupBtn.addEventListener("click", async () => {
    if (!callUI.activeCallId) return;
    if (
      capsuleCapture.active &&
      capsuleCapture.callId === callUI.activeCallId
    ) {
      await finishCapsuleCapture("user_finished");
      return;
    }
    const callId = callUI.activeCallId;
    hideActiveSurface();
    stopAllMedia();
    callUI.activeCallId = null;
    callUI.activeCallLocalRole = "";
    await callApiPost({ action: "hangup", call_id: callId });
  });
  const recordBtn = $$("#btn-call-record");
  if (recordBtn) recordBtn.addEventListener("click", async () => {
    if (!callUI.activeCallId) return;
    await callApiPost({
      action: "request_recording", call_id: callUI.activeCallId,
    });
  });
  // Tier α mute + camera-toggle. The user controls media; the
  // toggles flip MediaStreamTrack.enabled - track stays connected
  // (so DTLS-SRTP doesn't churn) but silently emits silence/black.
  const muteBtn = $$("#btn-call-mute");
  if (muteBtn) muteBtn.addEventListener("click", () => {
    if (!media.localStream) return;
    media.muted = !media.muted;
    media.localStream.getAudioTracks().forEach((t) => { t.enabled = !media.muted; });
    syncMuteCameraButtons();
  });
  const cameraBtn = $$("#btn-call-camera");
  if (cameraBtn) cameraBtn.addEventListener("click", () => {
    if (!media.localStream) return;
    media.cameraOff = !media.cameraOff;
    media.localStream.getVideoTracks().forEach((t) => { t.enabled = !media.cameraOff; });
    syncMuteCameraButtons();
  });
  // SAS confirmation pane - shown when the daemon's TrustLedger
  // reports first-contact (UNVERIFIED) OR a rotated key (CHAIN_OK).
  // Yes = user confirms the words match → daemon pins this peer.
  // No  = user reports a mismatch → daemon refuses + warns.
  function hideSasPane() {
    const pane = $$("#call-sas-pane");
    if (pane) {
      pane.style.display = "none";
      pane.classList.remove("show");
    }
    const words = $$("#call-sas-words");
    if (words) words.textContent = "";
  }
  const sasYesBtn = $$("#btn-sas-yes");
  if (sasYesBtn) sasYesBtn.addEventListener("click", async () => {
    if (callUI.activeCallId) {
      await callApiPost({
        action: "confirm_sas", call_id: callUI.activeCallId,
      });
    }
    hideSasPane();
  });
  const sasNoBtn = $$("#btn-sas-no");
  if (sasNoBtn) sasNoBtn.addEventListener("click", async () => {
    if (callUI.activeCallId) {
      await callApiPost({
        action: "decline_sas", call_id: callUI.activeCallId,
      });
      await callApiPost({
        action: "hangup", call_id: callUI.activeCallId,
      });
      hideActiveSurface();
      stopAllMedia();
      callUI.activeCallId = null;
    }
    hideSasPane();
  });

