// Isolated service: collaborators cross the factory parameter boundary.
//
// Owner of the peer page's daemon-chat view state: which conversation is
// open (a peer or a group, never both), the message selected as the reply
// target, and the roster rows the global search filters. Fields (read
// through `state.<name>`): daemon_active_peer, daemon_active_group,
// daemon_reply_to, daemon_roster_peers, daemon_roster_groups.
function createDaemonConversation() {
  let activePeer = null;
  let activeGroup = null;
  let replyTo = null;
  let rosterPeers;   // absent until the first roster fetch
  let rosterGroups;

  function openPeer(peer) {
    activePeer = peer;
    activeGroup = null;
  }

  function openGroup(group) {
    activePeer = null;
    activeGroup = group;
  }

  // Back to the roster.
  function close() {
    activePeer = null;
    activeGroup = null;
  }

  // The open group was left; any open peer chat is untouched.
  function leaveGroup() {
    activeGroup = null;
  }

  // A bounded preview of the message being replied to.
  function setReplyTo(message) {
    replyTo = {
      id: String(message.id || ""),
      body: String(message.body || message.file?.name || "(message)").slice(0, 160),
    };
    return replyTo;
  }

  function clearReplyTo() {
    replyTo = null;
  }

  // The daemon confirmed a change to a peer record the chat opened (the
  // same record object the roster lists), e.g. its alias or mute flag.
  function updatePeer(peer, changes) {
    if (!peer || typeof peer !== "object") throw new TypeError("updatePeer needs a peer record");
    Object.assign(peer, changes);
    return peer;
  }

  // The roster keeps its own copies; callers' arrays stay theirs.
  function replaceRoster(peers, groups) {
    rosterPeers = peers.slice();
    rosterGroups = groups.slice();
  }

  // Lifecycle: no conversation, no reply, no roster.
  function reset() {
    activePeer = null;
    activeGroup = null;
    replyTo = null;
    rosterPeers = undefined;
    rosterGroups = undefined;
  }

  return Object.freeze({
    activePeer: () => activePeer,
    activeGroup: () => activeGroup,
    replyTo: () => replyTo,
    rosterPeers: () => rosterPeers,
    rosterGroups: () => rosterGroups,
    openPeer,
    openGroup,
    close,
    leaveGroup,
    setReplyTo,
    clearReplyTo,
    updatePeer,
    replaceRoster,
    reset,
  });
}
