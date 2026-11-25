  // Local state - tracks the currently-shown call surface.
  const callUI = createCallState();
  // Expose for debug + tests
  if (typeof window !== "undefined") {
    window._livingPresenceCallUI = callUI;
  }

