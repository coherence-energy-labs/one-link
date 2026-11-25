// Isolated service: collaborators cross the factory parameter boundary.
//
// The peer page's shared read namespace. Identity session fields belong to
// createPeerIdentity() and daemon transport fields to createDaemonLink();
// both are published here read-only. The remaining shared fields
// (pairing session, daemon chat selection, diagnostics) are added by the
// features that use them.
function createPeerState() {
  const state = {};

  return state;
}
