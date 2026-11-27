// Isolated service: dependencies are explicit parameters; no owner closure access.
//
// The one route from the call driver (a separate closure) into the owner
// page's message rendering state. Published as window.__oneLinkCallLog. The
// driver asks it for a peer's short id and hands it synthesized CALL_LOG rows
// (missed / ended call bubbles); the row lands in the message store and the
// open conversation re-renders. Nothing else of the owner page is reachable
// through it.
function createCallLogBridge({ messageStore, getPeers, getSelectedPeer, renderMessages }) {
  if (!messageStore || typeof messageStore.appendCallLog !== "function") {
    throw new TypeError("createCallLogBridge needs the message store");
  }
  function peerShortIdForFp(fp) {
    if (!fp) return null;
    for (const p of getPeers().values()) {
      if (p.fingerprint === fp) return p.short_id;
    }
    return null;
  }
  function appendCallLog(row) {
    if (!row || row.t !== "CALL_LOG" || typeof row.id !== "string" || !row.id) {
      throw new TypeError("the call bubble bridge accepts CALL_LOG rows only");
    }
    messageStore.appendCallLog(row);
    if (row.peer === getSelectedPeer()) renderMessages();
  }
  return Object.freeze({ peerShortIdForFp, appendCallLog });
}
