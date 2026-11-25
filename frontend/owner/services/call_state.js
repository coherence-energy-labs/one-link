// Isolated service: dependencies are explicit parameters; no owner closure access.
//
// Owner of one call driver's call state: the active and inbound call
// identity, SDP/ICE negotiation bookkeeping, media telemetry and repair
// counters, backend recommendations, history, and the telemetry timers.
// `view` is the read path (the driver binds it as `callUI`); it is
// read-only. Scalar fields change through set / update / increment, which
// refuse undeclared fields. Collections, call tracking and lifecycle change
// only through the named transitions below. dispose() releases the timers.
function createCallState({ clearInterval } = {}) {
  const record = createOwnedRecord("callUI", {
    activeCallId: null,
    activeCallPeer: null,
    activeCallPeerFp: null,
    activeCallLocalRole: "",
    activeCallKind: undefined,
    inboundCallId: null,
    inboundCallPeer: null,
    inboundCallPeerFp: null,
    // An SDP offer that arrived before local media was ready.
    pendingRemoteOffer: undefined,
    pendingIceCandidates: [],
    appliedIceKeys: new Set(),
    appliedRemoteOfferKeys: new Set(),
    appliedRemoteAnswerKeys: new Set(),
    metricsTimer: null,
    mediaWatchdogTimer: null,
    oneEvents: [],
    localMediaReady: false,
    sdpOfferInFlight: false,
    sdpAnswerInFlight: false,
    lastLocalOfferSdp: "",
    lastLocalAnswerSdp: "",
    lastOfferSendMs: 0,
    lastAnswerSendMs: 0,
    lastLocalOfferCreatedMs: 0,
    remoteOfferCollisionCount: 0,
    lastMetricsSnapshot: null,
    lastFrameWarningMs: 0,
    lastMediaRepairMs: 0,
    lastInboundVideoBytes: 0,
    lastInboundAudioBytes: 0,
    lastInboundVideoFramesDecoded: 0,
    stalledMediaTicks: 0,
    frozenMediaTicks: 0,
    lastRemoteVideoTime: 0,
    lastRemoteAudioTime: 0,
    lastRemoteSurfaceSyncMs: 0,
    lastInboundPacketsLost: 0,
    lastInboundPacketsReceived: 0,
    qualityEwmaRttMs: null,
    qualityEwmaLoss: null,
    qualityBadTicks: 0,
    qualityGoodTicks: 0,
    lastUserVisibleRepairMs: 0,
    adaptationLevel: 0,
    tauPressureTicks: 0,
    tauStableTicks: 0,
    lastTauAdaptMs: 0,
    tauRiskEwma: null,
    tauCoherenceEwma: null,
    tauSurpriseEwma: null,
    tauBandwidthEwmaKbps: null,
    tauLastDecision: null,
    lastCaptureProfile: "",
    mediaRepairStage: 0,
    lastPlaybackReviveMs: 0,
    lastPcRebuildMs: 0,
    lastNetworkResumeRepairMs: 0,
    lastRemoteMediaMovingMs: 0,
    lastRepairDiagnosis: null,
    repairDiagnosisCounts: {},
    repairEscalationScore: 0,
    lastBackendRecommendation: null,
    lastBackendRecommendationKey: "",
    lastBackendRecommendationMs: 0,
    lastRecoveryIntent: null,
    lastRecoveryIntentKey: "",
    lastRecoveryIntentMs: 0,
    lastSessionAuthority: undefined,
    lastSessionAuthorityKey: undefined,
    lastSessionAuthorityMs: undefined,
    backendActionCooldowns: {},
    callHistory: [],
    callNotes: undefined,
    acceptedCallIds: new Set(),
    lastAcceptRetryMs: {},
    lastRejoinAttemptMs: {},
    autoTraceBuffer: [],
    lastAutoTraceMs: 0,
    lastAutoTraceKey: "",
    // Per-call lifecycle tracking for missed/ended call bubbles; created by
    // the event router when it starts.
    _callTracking: undefined,
  });
  const f = record.fields;

  // ── Call acceptance ──
  function acceptCall(callId) { f.acceptedCallIds.add(callId); }
  function forgetAcceptedCall(callId) { return f.acceptedCallIds.delete(callId); }
  function stampAcceptRetry(callId, at) { f.lastAcceptRetryMs[callId] = at; }
  function stampRejoinAttempt(callId, at) { f.lastRejoinAttemptMs[callId] = at; }

  // ── Signaling bookkeeping ──
  function markIceApplied(key) { f.appliedIceKeys.add(key); }
  function markRemoteOfferApplied(key) { f.appliedRemoteOfferKeys.add(key); }
  function markRemoteAnswerApplied(key) { f.appliedRemoteAnswerKeys.add(key); }
  function queueIceCandidate(candidate) { f.pendingIceCandidates.push(candidate); }
  // Remove and return every queued candidate, in arrival order.
  function takeQueuedIceCandidates() { return f.pendingIceCandidates.splice(0); }
  // A new peer connection: no queued candidates and no applied ICE keys.
  function forgetIceSignals() {
    f.pendingIceCandidates = [];
    f.appliedIceKeys.clear();
  }
  // A rebuilt peer connection also forgets applied offers/answers and any
  // SDP in flight.
  function forgetNegotiation() {
    forgetIceSignals();
    f.appliedRemoteOfferKeys.clear();
    f.appliedRemoteAnswerKeys.clear();
    f.sdpOfferInFlight = false;
    f.sdpAnswerInFlight = false;
    f.lastLocalOfferSdp = "";
    f.lastLocalAnswerSdp = "";
  }

  // ── Repair diagnosis ──
  // One more observation of `kind`, raising the escalation score by
  // `severity` (capped at 10). Returns the per-kind counts (for reading).
  function countRepairDiagnosis(kind, severity) {
    const counts = f.repairDiagnosisCounts || {};
    counts[kind] = Number(counts[kind] || 0) + 1;
    f.repairDiagnosisCounts = counts;
    f.repairEscalationScore = Math.min(10, Number(f.repairEscalationScore || 0) + severity);
    return counts;
  }
  function clearRepairDiagnosis() {
    f.repairDiagnosisCounts = {};
    f.lastRepairDiagnosis = null;
  }

  // ── Backend guidance ──
  function stampBackendCooldown(action, at) { f.backendActionCooldowns[action] = at; }

  // ── Bounded logs ──
  // The newest 12 automatic traces, newest first.
  function recordAutoTrace(payload) {
    f.autoTraceBuffer.unshift(payload);
    f.autoTraceBuffer = f.autoTraceBuffer.slice(0, 12);
  }
  function recordCallHistory(entry) {
    f.callHistory.unshift(entry);
    f.callHistory = f.callHistory.slice(0, 10);
  }
  function recordOneEvent(event) {
    f.oneEvents.unshift(event);
    f.oneEvents = f.oneEvents.slice(0, 4);
  }
  function clearOneEvents() { f.oneEvents = []; }

  // ── Per-call tracking (missed / ended bubbles) ──
  function startCallTracking() {
    if (!f._callTracking) f._callTracking = {};
  }
  function trackCall(callId, entry) { f._callTracking[callId] = entry; }
  function markTrackedCallActive(callId) {
    const t = f._callTracking[callId];
    if (t) t.reachedActive = true;
    return Boolean(t);
  }
  // Returns the tracked call, now ended, or null if it is unknown or
  // already ended.
  function endTrackedCall(callId, at) {
    const t = f._callTracking[callId];
    if (!t || t.endedAt) return null;
    t.endedAt = at;
    return t;
  }
  function forgetTrackedCall(callId) { delete f._callTracking[callId]; }

  // ── Lifecycle ──
  // Everything a finished call leaves behind in negotiation, telemetry,
  // quality, adaptation and repair state. Call identity, history, backend
  // guidance, timers and the event log are not per-media-session state.
  function resetMediaSession() {
    f.pendingIceCandidates = [];
    f.appliedIceKeys.clear();
    f.appliedRemoteOfferKeys.clear();
    f.appliedRemoteAnswerKeys.clear();
    f.localMediaReady = false;
    f.lastLocalOfferSdp = "";
    f.lastLocalAnswerSdp = "";
    f.lastOfferSendMs = 0;
    f.lastAnswerSendMs = 0;
    f.lastLocalOfferCreatedMs = 0;
    f.remoteOfferCollisionCount = 0;
    f.lastMetricsSnapshot = null;
    f.lastMediaRepairMs = 0;
    f.lastInboundVideoBytes = 0;
    f.lastInboundAudioBytes = 0;
    f.stalledMediaTicks = 0;
    f.lastInboundPacketsLost = 0;
    f.lastInboundPacketsReceived = 0;
    f.qualityEwmaRttMs = null;
    f.qualityEwmaLoss = null;
    f.qualityBadTicks = 0;
    f.qualityGoodTicks = 0;
    f.lastUserVisibleRepairMs = 0;
    f.adaptationLevel = 0;
    f.tauPressureTicks = 0;
    f.tauStableTicks = 0;
    f.lastTauAdaptMs = 0;
    f.tauRiskEwma = null;
    f.tauCoherenceEwma = null;
    f.tauSurpriseEwma = null;
    f.tauBandwidthEwmaKbps = null;
    f.tauLastDecision = null;
    f.lastCaptureProfile = "";
    f.mediaRepairStage = 0;
    f.lastPlaybackReviveMs = 0;
    f.lastPcRebuildMs = 0;
    f.lastRemoteMediaMovingMs = 0;
    f.lastRepairDiagnosis = null;
    f.repairDiagnosisCounts = {};
    f.repairEscalationScore = 0;
    f.acceptedCallIds.clear();
    f.lastAcceptRetryMs = {};
  }

  // Release the telemetry timers this state holds.
  function dispose() {
    if (typeof clearInterval === "function") {
      if (f.metricsTimer) clearInterval(f.metricsTimer);
      if (f.mediaWatchdogTimer) clearInterval(f.mediaWatchdogTimer);
    }
    f.metricsTimer = null;
    f.mediaWatchdogTimer = null;
  }

  return Object.freeze({
    view: record.view,
    set: record.set,
    update: record.update,
    increment: record.increment,
    acceptCall,
    forgetAcceptedCall,
    stampAcceptRetry,
    stampRejoinAttempt,
    markIceApplied,
    markRemoteOfferApplied,
    markRemoteAnswerApplied,
    queueIceCandidate,
    takeQueuedIceCandidates,
    forgetIceSignals,
    forgetNegotiation,
    countRepairDiagnosis,
    clearRepairDiagnosis,
    stampBackendCooldown,
    recordAutoTrace,
    recordCallHistory,
    recordOneEvent,
    clearOneEvents,
    startCallTracking,
    trackCall,
    markTrackedCallActive,
    endTrackedCall,
    forgetTrackedCall,
    resetMediaSession,
    dispose,
  });
}
