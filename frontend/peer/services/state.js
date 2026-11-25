// Isolated service: collaborators cross the factory parameter boundary.
function createPeerState() {
  const state = {
    rec: null,
    envelope: null,
    pending_rec: null,
    pending_authority: null,
    post_identity_flow_started: false,
  };

  return state;
}
