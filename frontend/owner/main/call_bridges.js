  // ── Owner-page services for the call driver (MNT-03) ───────────────
  // The call driver runs in its own closure, so none of this closure's
  // names (state, api, toast, selectPeer, ...) are in scope there. It gets
  // exactly these two explicit bridges and nothing else:
  //   __oneLinkCallLog   missed/ended call bubbles into the message store
  //   __oneLinkCallHost  the owner services the driver's UI uses
  // tests/js/ownership_census.js fails the build if the driver names an
  // owner-closure binding directly again.
  window.__oneLinkCallLog = createCallLogBridge({
    messageStore,
    getPeers: () => state.peers,
    getSelectedPeer: () => state.selectedPeer,
    renderMessages: () => renderMessages(),
  });
  window.__oneLinkCallHost = Object.freeze({
    post: (path, body) => api.post(path, body),
    upload: (peerId, file, opts) => api.upload(peerId, file, opts),
    newClientMsgId: () => _newClientMsgId(),
    toast: (message, kind, ms) => toast(message, kind, ms),
    errorToastBody: (error) => errorToastBody(error),
    returnToOneHealthGuideIfPending: () => returnToOneHealthGuideIfPending(),
    selectPeer: (peerId) => selectPeer(peerId),
  });
