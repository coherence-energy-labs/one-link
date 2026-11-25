// Isolated service: collaborators cross the factory parameter boundary.
//
// Owner of the peer page's identity session. The unwrapped identity record
// lives only in memory after unlock; the passphrase is never kept. Fields
// (read through `state.<name>`):
//   rec                         unlocked identity record, or null
//   envelope                    the wrapped envelope committed on disk
//   pending_rec / pending_authority
//                               a fresh or legacy identity awaiting its
//                               first encrypted commit, and the storage
//                               authority it must replace
//   boot_error_msg              why boot stopped (absent until it does)
//   post_identity_flow_started  the post-unlock flow runs once per page
function createPeerIdentity() {
  let rec = null;
  let envelope = null;
  let pendingRec = null;
  let pendingAuthority = null;
  let bootError;
  let postIdentityFlowStarted = false;

  // Protection required: the record is held aside, not usable, until its
  // encrypted commit replaces `authority` (null for a fresh identity).
  function stagePending(record, authority) {
    rec = null;
    envelope = null;
    pendingRec = record;
    pendingAuthority = authority;
  }

  // The authenticated private identity is available.
  function unlock(record, committedEnvelope) {
    rec = record;
    envelope = committedEnvelope;
    pendingRec = null;
    pendingAuthority = null;
  }

  // A wrapped envelope was found on disk, or a rotation committed.
  function setEnvelope(next) {
    envelope = next;
  }

  function failBoot(message) {
    bootError = message;
  }

  // Returns true exactly once, and only with an unlocked identity.
  function beginPostIdentityFlow() {
    if (!rec || postIdentityFlowStarted) return false;
    postIdentityFlowStarted = true;
    return true;
  }

  // Lifecycle: forget the in-memory identity (sign-out, reset). The disk
  // authority is the identity feature's concern, not this owner's.
  function reset() {
    rec = null;
    envelope = null;
    pendingRec = null;
    pendingAuthority = null;
    bootError = undefined;
    postIdentityFlowStarted = false;
  }

  return Object.freeze({
    rec: () => rec,
    envelope: () => envelope,
    pendingRec: () => pendingRec,
    pendingAuthority: () => pendingAuthority,
    bootError: () => bootError,
    postIdentityFlowStarted: () => postIdentityFlowStarted,
    stagePending,
    unlock,
    setEnvelope,
    failBoot,
    beginPostIdentityFlow,
    reset,
  });
}
