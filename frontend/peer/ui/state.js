  // ── session state ──────────────────────────────────────────────────
  // The unwrapped identity record lives only in memory after unlock.
  // We intentionally don't keep the passphrase in memory — it's
  // discarded after deriving the AES key. To re-encrypt with a new
  // passphrase we need the user to re-enter the old one (proves
  // possession), or to re-wrap from the in-memory `state.rec`.
  const state = createPeerState();

