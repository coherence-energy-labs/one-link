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
    callUI, media, setReconnectState, updateCallQuality, targetMediaProfile, applyCaptureProfileForTau, updateOneChip, addOneCallEvent, reportCallEvent,
  });

