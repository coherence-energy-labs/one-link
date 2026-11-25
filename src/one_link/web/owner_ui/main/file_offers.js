  // ── Accept-first: incoming-file offer prompts ───────────────────
  // A standalone file someone sends now WAITS for the user's OK (unless
  // the "Always ask" setting is off). The daemon broadcasts
  // file_offer_pending; we show a persistent prompt with Accept /
  // Decline (and Accept-all-from-them so a multi-file send is one tap).
  function _fileOfferBytes(n) {
    try { return _humanBytes(n || 0); } catch (_e) { return `${n || 0} B`; }
  }
  // Strip the internal staging prefix the sender's upload pipeline
  // adds for collision avoidance (<timestamp>_<hex>_<original_name>).
  // Recursively, in case a file has been forwarded multiple times.
  // Defense in depth — the sender now sends the clean name on the
  // wire (display_name on FILE_OFFER), but old messages in chat
  // history + cross-version peers still benefit from cleaning here.
  function _cleanFileName(name) {
    if (!name) return name;
    let out = String(name);
    for (let i = 0; i < 4; i += 1) {
      const next = out.replace(/^\d{13,}_[0-9a-fA-F]{8,}_/, "");
      if (next === out) break;
      out = next;
    }
    return out;
  }
  async function acceptFileOffer(tid, all) {
    try {
      const path = `/api/transfers/${encodeURIComponent(tid)}/accept`;
      await api.post(all ? path + "?all=1" : path, {});
    } catch (e) { toast(`Couldn't accept: ${e}`, "error", 4000); }
  }
  async function declineFileOffer(tid, all) {
    try {
      const path = `/api/transfers/${encodeURIComponent(tid)}/decline`;
      await api.post(all ? path + "?all=1" : path, {});
    } catch (e) { toast(`Couldn't decline: ${e}`, "error", 4000); }
  }
  // Per-peer grouped pending offers. One card per peer; buttons cover
  // all of that peer's pending offers at once (the API supports ?all=1
  // for accept-all / decline-all from the peer). N==1 collapses to
  // "Accept" / "Decline" so a single file doesn't say "Accept all".
  // _byTid is a tid → peer_fp index for fast removal on WS resolve.
  function _ensurePendingState() {
    if (!state.pendingFileOffersByPeer) state.pendingFileOffersByPeer = {};
    if (!state.pendingFileOfferPeerEls) state.pendingFileOfferPeerEls = {};
    if (!state.pendingFileOfferByTid) state.pendingFileOfferByTid = {};
  }
  function _renderPeerFileOfferCard(peerFp) {
    _ensurePendingState();
    const offers = state.pendingFileOffersByPeer[peerFp] || [];
    const prior = state.pendingFileOfferPeerEls[peerFp];
    if (prior) prior.remove();
    if (offers.length === 0) {
      delete state.pendingFileOfferPeerEls[peerFp];
      return;
    }
    const card = el("div", "toast info file-offer-prompt");
    card.style.display = "flex";
    card.style.flexDirection = "column";
    card.style.gap = "8px";
    const who = offers[0].peer_short_id
      || (peerFp || "").slice(0, 12) || "Someone";
    const intro = offers.length === 1
      ? `${who} wants to send you:`
      : `${who} wants to send you ${offers.length} files:`;
    card.appendChild(el("div", "", intro));
    const list = el("div", "");
    list.style.display = "flex";
    list.style.flexDirection = "column";
    list.style.gap = "2px";
    for (const o of offers) {
      const line = el(
        "div", "",
        `${_cleanFileName(o.name) || "a file"} · ${_fileOfferBytes(o.size)}`,
      );
      line.style.fontWeight = "600";
      line.title = _cleanFileName(o.name) || "";
      list.appendChild(line);
    }
    card.appendChild(list);
    const row = el("div", "");
    row.style.display = "flex";
    row.style.gap = "8px";
    row.style.flexWrap = "wrap";
    const bulk = offers.length > 1;
    const acceptLabel = bulk ? `Accept all (${offers.length})` : "Accept";
    const declineLabel = bulk ? "Decline all" : "Decline";
    const accept = el("button", "btn-accept", acceptLabel);
    accept.onclick = async () => {
      const firstTid = offers[0].transfer_id;
      for (const o of offers) {
        delete state.pendingFileOfferByTid[o.transfer_id];
      }
      state.pendingFileOffersByPeer[peerFp] = [];
      _renderPeerFileOfferCard(peerFp);
      await acceptFileOffer(firstTid, bulk);
    };
    const decline = el("button", "", declineLabel);
    decline.onclick = async () => {
      const firstTid = offers[0].transfer_id;
      for (const o of offers) {
        delete state.pendingFileOfferByTid[o.transfer_id];
      }
      state.pendingFileOffersByPeer[peerFp] = [];
      _renderPeerFileOfferCard(peerFp);
      await declineFileOffer(firstTid, bulk);
    };
    row.appendChild(accept);
    row.appendChild(decline);
    card.appendChild(row);
    const host = $("#toasts");
    if (host) host.appendChild(card);
    state.pendingFileOfferPeerEls[peerFp] = card;
  }
  function _addPendingFileOffer(o) {
    if (!o || !o.transfer_id || !o.peer_fp) return;
    _ensurePendingState();
    if (state.pendingFileOfferByTid[o.transfer_id]) return;  // dup
    const list = state.pendingFileOffersByPeer[o.peer_fp]
      || (state.pendingFileOffersByPeer[o.peer_fp] = []);
    list.push(o);
    state.pendingFileOfferByTid[o.transfer_id] = o.peer_fp;
    _renderPeerFileOfferCard(o.peer_fp);
  }
  function _removeFileOfferPrompt(tid) {
    _ensurePendingState();
    const peerFp = state.pendingFileOfferByTid[tid];
    if (!peerFp) return;
    const list = state.pendingFileOffersByPeer[peerFp] || [];
    state.pendingFileOffersByPeer[peerFp] = list.filter(o => o.transfer_id !== tid);
    delete state.pendingFileOfferByTid[tid];
    _renderPeerFileOfferCard(peerFp);
  }
  // Back-compat shim for the WS handler call site.
  function showFileOfferPrompt(o) { _addPendingFileOffer(o); }
  async function refreshPendingFileOffers() {
    try {
      const r = await api.get("/api/transfers/pending");
      for (const o of (r.offers || [])) _addPendingFileOffer(o);
    } catch (_e) { /* offline / not ready */ }
  }

