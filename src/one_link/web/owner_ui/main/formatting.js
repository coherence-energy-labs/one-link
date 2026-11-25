  // ── Tiny helpers ────────────────────────────────────────────────────
  const {
    $,
    el,
    fmtBytes,
    fmtRate,
    fmtMbps,
    fmtEta,
    fmtTime,
    sameDay,
    dayLabel,
    initials,
    displayFileName,
    _middleTruncatePath,
    fileIcon,
  } = createOwnerFormatting({
    document, getSettings: () => state.runtimeSettings,
  });

