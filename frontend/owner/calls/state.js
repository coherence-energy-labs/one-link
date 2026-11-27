  // Local state - tracks the currently-shown call surface. callState owns
  // it; `callUI` is its read-only view (MNT-03).
  const callState = createCallState({ clearInterval: (id) => clearInterval(id) });
  const callUI = callState.view;
  // Expose for debug + tests
  if (typeof window !== "undefined") {
    window._livingPresenceCallUI = callUI;
  }

