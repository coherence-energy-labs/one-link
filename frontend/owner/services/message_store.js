// Isolated service: dependencies are explicit parameters; no owner closure access.
//
// Owner of the in-memory conversation history the renderers draw: the
// recent direct messages across all peers, and the selected group's
// messages. Live events, optimistic sends, send-state updates and local
// clears all change it here; renderers read it through `state.messages` and
// `state.groupMessages`. Message rows themselves stay plain objects so the
// renderers and their hashes see exactly the fields the daemon sent.
function createMessageStore() {
  // Direct history is capped: past 1000 rows the newest 800 are kept.
  const DIRECT_CAP = 1000;
  const DIRECT_KEEP = 800;

  let direct = [];
  let group = [];

  function rows(scope) {
    if (scope === "direct") return direct;
    if (scope === "group") return group;
    throw new TypeError(`unknown message scope: ${scope}`);
  }

  function find(scope, id) {
    return rows(scope).find((x) => x.id === id) || null;
  }

  // GET /api/messages replaced the direct history (the value is kept as
  // returned, as before).
  function replaceDirect(messages) {
    direct = messages;
  }

  function replaceGroup(messages) {
    group = messages;
  }

  function clearGroup() {
    group = [];
  }

  // Local chat history was wiped.
  function clearAll() {
    direct = [];
    group = [];
  }

  // An optimistic bubble for a send the daemon has not confirmed yet.
  function appendDirect(message) {
    direct.push(message);
  }

  // A `msg` event. An id already painted (an optimistic bubble whose
  // client_msg_id the daemon threaded through, or a repeated echo) is
  // replaced by one canonical row marked sent; local-only fields the event
  // lacks are kept. Returns the canonical row.
  function receiveDirect(message) {
    const dupIdx = direct.findIndex((x) => x.id === message.id);
    let row;
    if (dupIdx >= 0) {
      const prev = direct[dupIdx];
      row = {
        ...prev, ...message,
        _sendingState: "sent",
        _error: undefined,
        _queueReason: undefined,
      };
      direct[dupIdx] = row;
    } else {
      row = message;
      direct.push(message);
    }
    if (direct.length > DIRECT_CAP) direct = direct.slice(-DIRECT_KEEP);
    return row;
  }

  // A synthesized CALL_LOG row (missed / ended call) from the call driver.
  function appendCallLog(row) {
    direct.push(row);
    if (direct.length > DIRECT_CAP) direct = direct.slice(-DIRECT_KEEP);
    return row;
  }

  // A `group_msg` row for the open group: merged into a known id, otherwise
  // prepended (group history is newest-first).
  function upsertGroupRow(row) {
    const idx = group.findIndex((x) => x.id === row.id);
    if (idx >= 0) group[idx] = { ...group[idx], ...row };
    else group.unshift(row);
  }

  // Live edit. Returns whether the target was in memory.
  function editMessage(scope, id, body, editedAtMs) {
    const target = find(scope, id);
    if (!target) return false;
    target.body = body;
    target.edited_at_ms = editedAtMs;
    return true;
  }

  // Live delete: the row stays as a tombstone.
  function tombstoneMessage(scope, id, deletedAtMs) {
    const target = find(scope, id);
    if (!target) return false;
    target.body = null;
    target.deleted = true;
    target.deleted_at_ms = deletedAtMs;
    return true;
  }

  // Live reaction add/remove from one peer fingerprint. An emoji whose last
  // reactor left is removed. Returns whether the target was in memory.
  function applyReaction(scope, id, op, emoji, peerFp) {
    const target = find(scope, id);
    if (!target) return false;
    target.reactions = target.reactions || {};
    if (op === "add") {
      target.reactions[emoji] = target.reactions[emoji] || [];
      if (!target.reactions[emoji].includes(peerFp)) target.reactions[emoji].push(peerFp);
    } else if (target.reactions[emoji]) {
      target.reactions[emoji] = target.reactions[emoji].filter((f) => f !== peerFp);
      if (target.reactions[emoji].length === 0) delete target.reactions[emoji];
    }
    return true;
  }

  // One outbound bubble's send-state (sending / sent / queued / failed).
  // A tombstoned row is never decorated (2026-05-22 audit Batch AA): a
  // deleted message must not render with a "sent" tick. Returns the updated
  // row, or null when nothing changed.
  function markSendState(id, sendingState, extras = {}) {
    const idx = direct.findIndex((x) => x.id === id);
    if (idx < 0) return null;
    const current = direct[idx];
    if (current.deleted_at_ms || current.body === "[message deleted]") return null;
    direct[idx] = { ...current, _sendingState: sendingState, ...extras };
    return direct[idx];
  }

  // Lifecycle: the empty history a new page starts with.
  function reset() {
    clearAll();
  }

  return Object.freeze({
    direct: () => direct,
    group: () => group,
    find,
    replaceDirect,
    replaceGroup,
    clearGroup,
    clearAll,
    appendDirect,
    receiveDirect,
    appendCallLog,
    upsertGroupRow,
    editMessage,
    tombstoneMessage,
    applyReaction,
    markSendState,
    reset,
  });
}
