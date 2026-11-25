  const {
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
  } = createCallHealth({
    callUI, callState, media, setReconnectState, updateCallQuality, targetMediaProfile, applyCaptureProfileForTau, updateOneChip, addOneCallEvent, reportCallEvent,
  });

