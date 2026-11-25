// Isolated service: dependencies are explicit parameters; no owner closure access.
//
// Owner of the page's mirror of the daemon's transfer ledger. The daemon is
// the source of transfer truth; this store holds the most recent rows the
// page has seen, the by-id map file bubbles read, the lazily built
// (direction|blob) index, and the per-transfer EWMA rate tracker. Every
// change happens here. Readers see the live collections through `state`.
function createTransferStore({ now }) {
  if (typeof now !== "function") throw new TypeError("createTransferStore needs a clock");
  // The WebSocket path keeps the newest 80 rows; evicted rows also leave
  // the by-id map and the index (2026-05-22 audit Batch AA).
  const RECENT_LIMIT = 80;
  // v0.8.8: EWMA alpha for bytes/second. Smooths chunk-by-chunk bursts
  // without going stale on slow links.
  const _RATE_ALPHA = 0.4;

  let list = [];
  let byId = new Map();
  let byDirBlob = null; // built on first lookup, then maintained incrementally
  const rates = new Map(); // id -> { lastBytes, lastTs, bps }

  function dirBlobKey(t) {
    const blob = (t?.blob_hash || "").toLowerCase();
    return blob && t.direction ? `${t.direction}|${blob}` : null;
  }

  function rebuildDirBlobIndex() {
    const idx = new Map();
    for (const t of byId.values()) {
      const key = dirBlobKey(t);
      if (key) idx.set(key, t);
    }
    byDirBlob = idx;
  }

  // Incremental path for the WebSocket handler; avoids a full rebuild per
  // transfer event. Without an index yet, build it.
  function trackDirBlob(t) {
    if (!byDirBlob) {
      rebuildDirBlobIndex();
      return;
    }
    const key = dirBlobKey(t);
    if (key) byDirBlob.set(key, t);
  }

  // A full snapshot from GET /api/transfers.
  function replaceAll(transfers) {
    list = transfers;
    byId = new Map();
    for (const t of list) byId.set(t.id, t);
  }

  // A live `transfer` event: replace or prepend the row, keep newest-first,
  // cap the list, prune evicted rows from the map and index, then record
  // the row in both.
  function applyEvent(transfer) {
    const idx = list.findIndex((t) => t.id === transfer.id);
    if (idx >= 0) list.splice(idx, 1, transfer);
    else list.unshift(transfer);
    list.sort((a, b) => (b.updated_ms || 0) - (a.updated_ms || 0));
    const evictedIds = list.slice(RECENT_LIMIT).map((t) => t.id);
    list = list.slice(0, RECENT_LIMIT);
    for (const eid of evictedIds) {
      byId.delete(eid);
      if (byDirBlob) {
        for (const [key, val] of byDirBlob) {
          if (val && val.id === eid) byDirBlob.delete(key);
        }
      }
    }
    byId.set(transfer.id, transfer);
    trackDirBlob(transfer);
  }

  // Local history was cleared: drop the rows and the by-id map. The index
  // and rate tracker are left as they were; the caller refreshes the ledger
  // immediately afterwards, as before this owner existed.
  function clearRecords() {
    list = [];
    byId = new Map();
  }

  // A row the user cleared from the transfer panel leaves the list only.
  function dropListed(id) {
    list = list.filter((x) => x.id !== id);
  }

  // The user cancelled active rows; reflect it before the WebSocket
  // round-trip confirms. Returns whether the row was known.
  function markCancelledByUser(id) {
    const rec = byId.get(id);
    if (!rec) return false;
    rec.status = "failed";
    rec.metadata = {
      ...(rec.metadata || {}),
      error: "cancelled by user",
      error_class: "CancelledByUser",
    };
    return true;
  }

  // Terminal rows forget their rate so a retry of the same id starts clean.
  function forgetRate(id) {
    return rates.delete(id);
  }

  // One progress snapshot of a non-terminal transfer.
  function sampleRate(t) {
    if (t.status !== "active" && t.status !== "offered") {
      // queued / paused: keep the last bps, restamp so a resume's first
      // delta is reasonable.
      const cur = rates.get(t.id) || {};
      cur.lastBytes = t.progress_bytes || 0;
      cur.lastTs = now();
      rates.set(t.id, cur);
      return;
    }
    const at = now();
    const prev = rates.get(t.id);
    if (!prev) {
      rates.set(t.id, { lastBytes: t.progress_bytes || 0, lastTs: at, bps: 0 });
      return;
    }
    const dt = (at - prev.lastTs) / 1000;
    if (dt < 0.1) return; // <100ms gaps are too noisy
    const db = (t.progress_bytes || 0) - prev.lastBytes;
    if (db < 0) {
      // progress went backwards (resume / retry): restart.
      rates.set(t.id, { lastBytes: t.progress_bytes || 0, lastTs: at, bps: 0 });
      return;
    }
    const inst = db / dt;
    const ewma = (1 - _RATE_ALPHA) * (prev.bps || 0) + _RATE_ALPHA * inst;
    rates.set(t.id, { lastBytes: t.progress_bytes || 0, lastTs: at, bps: ewma });
  }

  // Lifecycle: a fresh, empty mirror (the same state a new page starts in).
  function reset() {
    list = [];
    byId = new Map();
    byDirBlob = null;
    rates.clear();
  }

  return Object.freeze({
    list: () => list,
    byId: () => byId,
    dirBlobIndex: () => byDirBlob,
    rates: () => rates,
    replaceAll,
    applyEvent,
    clearRecords,
    dropListed,
    markCancelledByUser,
    rebuildDirBlobIndex,
    trackDirBlob,
    forgetRate,
    sampleRate,
    reset,
  });
}
