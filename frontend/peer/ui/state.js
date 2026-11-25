  // ── session state ──────────────────────────────────────────────────
  // The unwrapped identity record lives only in memory after unlock.
  // We intentionally don't keep the passphrase in memory — it's
  // discarded after deriving the AES key. To re-encrypt with a new
  // passphrase we need the user to re-enter the old one (proves
  // possession), or to re-wrap from the in-memory `state.rec`.
  const state = createPeerState();
  // Feature state owners (MNT-03): identity here, daemon transport in
  // daemon_chat/authority.js. `state.<field>` stays the read path; writing a
  // published field throws and names its owner.
  const stateOwners = createStatePublisher(state);
  const peerIdentity = createPeerIdentity();
  stateOwners.publish("peerIdentity", {
    rec: peerIdentity.rec,
    envelope: peerIdentity.envelope,
    pending_rec: peerIdentity.pendingRec,
    pending_authority: peerIdentity.pendingAuthority,
    boot_error_msg: peerIdentity.bootError,
    post_identity_flow_started: peerIdentity.postIdentityFlowStarted,
  });

