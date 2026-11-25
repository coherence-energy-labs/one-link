// Isolated service: dependencies are explicit parameters; no owner closure access.
function createOwnerState() {
  const state = {
    me: null,
    peers: new Map(),     // short_id -> peer
    hiddenLocalPeers: 0,
    selectedPeer: null,   // short_id
    messages: [],         // recent across all peers
    transfers: [],
    transfersById: new Map(),  // id -> transfer record (fast lookup for msg status)
    // v0.8.8: per-transfer rate tracker. Each entry is
    // {lastBytes, lastTs, bps} where bps is a rolling EWMA (alpha=0.4).
    // Cleared on transfer completion / failure.
    transferRates: new Map(),
    folders: [],
    status: null,
    fabric: null,
    selfMesh: null,
    oneSetup: null,
    oneHealth: null,
    searchQuery: "",
    searchResults: null,
    activePane: "convo",
    pairing: { peerFp: null, sas: null, sasPhrase: "", weConfirmed: false },
    staged: [],           // [{id, clientDeliveryId, file, dataUrl?}] pending send
    stagedSeq: 0,
    // A composer intent is captured exactly once.  Keyboard, button, and
    // programmatic sendCurrent() calls all pass through this mutex so an Enter
    // key repeat cannot submit the same text/attachments twice while the first
    // request is awaiting the daemon.
    composerSendInFlight: false,
    filesMode: "received",  // "received" | "sent"
    // v0.7.5: when set, the next sendCurrent threads its TEXT
    // under this parent message id (becomes msg.reply_to on the wire).
    replyTo: null,
    // v0.7.6: peer_fp -> highest ts_ms we know they've read.
    // Drives the ✓✓ checkmark on our outbound messages.
    readMarkers: {},
    // v0.7.6: monotonic-per-peer "highest ts of theirs we've already
    // ACKed back as read" - prevents redundant network calls.
    sentReadUpTo: {},
    // v0.8.0: groups. {group_id_hex: {name, member_count, my_role}}.
    groups: new Map(),
    // When user clicks a group in the sidebar, we set this. Mutually
    // exclusive with selectedPeer (entering a group exits 1:1 view).
    selectedGroup: null,  // group_id_hex or null
    groupMessages: [],    // current group's messages, refreshed on switch
    // Ephemeral group_id -> peer fingerprint -> expiry deadline. This is
    // deliberately memory-only; composition metadata never enters history.
    groupTyping: {},
    courierGuideMode: "send",
    groupDetail: null,    // {members, my_role, name, ...}
    pins: {},
    drafts: {},
    // Living Presence Tier α-pre - Reality dot state.
    // Map<blob_hex, {kind, path, recording, verified, produced_at_us}>.
    // Populated by the "frame_provenance" WS event when the daemon
    // verifies an inbound FILE_PROVENANCE message (see
    // docs/LIVING_PRESENCE_ARCHITECTURE.md §9.3 for the daemon-side
    // wiring). When the map is empty (today, pre-daemon-hook), the
    // Reality dot does not surface - that's Doctrine §3.5.c (no
    // surreptitious indicators; if we don't know, we don't say).
    provenanceByBlob: new Map(),
    // v0.21.x: in-memory cache of recently-uploaded outbound files,
    // keyed by `${name}|${size}`. Lets the sender click their own
    // outbound file bubble to re-open the photo/file they just sent
    // — the daemon stages uploads to a temp dir then deletes them
    // post-send, so without this cache the sender's bubble would
    // dead-end. Entry shape: {file: File, addedAt: ms, objectUrl: string|null}.
    // Lives across renders; cleared on tab close (best-effort, by design).
    outboundFileCache: new Map(),
    // v0.21.x: unread counters drive the tab title prefix "(N) One
    // Link" and the OS-level app badge (taskbar / dock). Keyed by
    // peer short_id. Incremented on every inbound TEXT / FILE
    // when (a) we're not focused on that peer AND (b) the window
    // is not focused. Cleared on selectPeer + on window focus.
    unreadByPeer: {},
    totalUnread: 0,
  };
  return state;
}
