// Isolated service: dependencies are explicit parameters; no owner closure access.
//
// Owner of one call driver's media and route state: streams, the peer
// connection, ICE/route policy, and the user's in-call controls. `view` is
// the read path (the driver binds it as `media`); it is read-only. Fields
// change through set / update (which refuse undeclared fields) and the reset
// transitions below. Capture and cleanup features own the browser resources'
// lifetime (stopping tracks, closing the connection); this owner forgets
// them.
function createCallMediaState() {
  const record = createOwnedRecord("media", {
    localStream: null,        // MediaStream from getUserMedia
    remoteStream: null,        // assembled from ontrack events
    pc: null,                  // RTCPeerConnection (when wired)
    iceConfigReady: null,      // Promise that resolves after STUN config is applied
    localCandidateAddresses: [], // daemon-observed, same-device/LAN numeric routes
    iceSignalChain: Promise.resolve(), // serialize candidates before end-of-candidates
    screenStream: null,
    cameraVideoTrack: null,
    screenSharing: false,
    backgroundBlur: false,
    // doctrine-ok: §3.2.a internal recovery state field; user copy stays calm.
    reconnecting: false,
    expectRemoteVideo: false,
    expectRemoteAudio: true,
    transceiversReady: false,
    held: false,
    captionsOn: false,
    captionsStarting: false,
    captionRecognizer: null,
    layoutMode: "focus",
    voiceProcessing: "smart",
    muted: false,
    cameraOff: false,
    selectedAudioInputId: "",
    selectedVideoInputId: "",
    selectedAudioOutputId: "",
    videoFit: "cover",
    iceHelperReady: false,
    iceRelayReady: false,
    routePolicy: "direct_first",
    routePolicyDetail: null,
    bestRelayHealth: "",
    bestRelayScore: null,
    turnCredentialExpiresAtMs: null,
    lastIceConfigRefreshMs: 0,
    lastRelayProbeMs: 0,
    forceRelayOnRepair: false,
    preferRelayNext: false,
  });
  const f = record.fields;

  // The daemon's route policy for this call (from ICE config, a relay
  // probe or a metrics report): the policy itself, the best relay's health
  // and score, and when the TURN credential expires.
  function recordRoutePolicy(policy) {
    f.routePolicyDetail = policy || null;
    f.bestRelayHealth = String(policy?.best_relay_health || "");
    f.bestRelayScore = Number.isFinite(Number(policy?.best_relay_score))
      ? Number(policy.best_relay_score)
      : null;
    f.turnCredentialExpiresAtMs = Number(policy?.credential_expires_at_ms || 0) || null;
  }

  // A finished call's ICE and route state: no pending config, no
  // candidates, an idle candidate chain, the default direct-first policy.
  function resetRoute() {
    f.iceConfigReady = null;
    f.localCandidateAddresses = [];
    f.iceSignalChain = Promise.resolve();
    f.iceHelperReady = false;
    f.iceRelayReady = false;
    f.routePolicy = "direct_first";
    f.forceRelayOnRepair = false;
    f.preferRelayNext = false;
    f.transceiversReady = false;
  }

  // A finished call's session controls: no screen share, effects, hold,
  // reconnect banner or caption start in progress; expect audio only.
  function resetSessionControls() {
    f.screenStream = null;
    f.cameraVideoTrack = null;
    f.screenSharing = false;
    f.backgroundBlur = false;
    // doctrine-ok: §3.2.a internal recovery state reset; user copy stays calm.
    f.reconnecting = false;
    f.expectRemoteVideo = false;
    f.expectRemoteAudio = true;
    f.transceiversReady = false;
    f.held = false;
    f.captionsStarting = false;
  }

  // A finished call's layout, voice processing, mute and camera choices.
  function resetPresentation() {
    f.layoutMode = "focus";
    f.voiceProcessing = "smart";
    f.muted = false;
    f.cameraOff = false;
  }

  return Object.freeze({
    view: record.view,
    set: record.set,
    update: record.update,
    recordRoutePolicy,
    resetRoute,
    resetSessionControls,
    resetPresentation,
  });
}
