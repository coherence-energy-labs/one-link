  // ── v0.19.0 — experimental transport-selector helpers ───────────────
  //
  // These score/storage helpers are not wired into the production send path
  // and do not justify advertising WebTransport. They remain isolated for
  // evaluation until a server endpoint, real transfer consumer, and live
  // migration proof exist. The shipped browser path is WebRTC.
  const PATH_STATS_DB = "one-link-peer-path-stats";
  const PATH_STATS_STORE = "path_stats.v1";
  const PATH_STATS_VERSION = 1;
  const PATH_EWMA_ALPHA = 0.28;
  const PATH_EPSILON_BASE = 0.08;
  const PATH_FAILURE_PENALTY = 0.70;

  function browserTransportCapabilities() {
    const caps = ["browser_peer", "manual_signal_v1"];
    if (window.RTCPeerConnection) caps.push("webrtc_v1");
    return caps;
  }

  function _pathStatKey(peerFp, pathKind) {
    return `${peerFp || "unknown"}::${pathKind}`;
  }

  function _defaultPathStat(peerFp, pathKind) {
    return {
      peer_fp: peerFp || "unknown",
      path_kind: pathKind,
      ewma_throughput_bps: 0,
      ewma_failure_rate: 0,
      last_used_ms: 0,
      samples: 0,
    };
  }

  function _openPathStatsDb() {
    return new Promise((resolve, reject) => {
      if (!window.indexedDB) {
        reject(new Error("IndexedDB unavailable"));
        return;
      }
      const req = indexedDB.open(PATH_STATS_DB, PATH_STATS_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(PATH_STATS_STORE)) {
          db.createObjectStore(PATH_STATS_STORE, { keyPath: "id" });
        }
      };
      req.onerror = () => reject(req.error || new Error("IndexedDB open failed"));
      req.onsuccess = () => resolve(req.result);
    });
  }

  async function loadPathStats(peerFp) {
    const db = await _openPathStatsDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(PATH_STATS_STORE, "readonly");
      const store = tx.objectStore(PATH_STATS_STORE);
      const req = store.getAll();
      req.onerror = () => reject(req.error || new Error("path stats read failed"));
      req.onsuccess = () => {
        const prefix = `${peerFp || "unknown"}::`;
        resolve((req.result || [])
          .filter((r) => String(r.id || "").startsWith(prefix))
          .map((r) => Object.assign({}, r, { id: undefined })));
      };
      tx.oncomplete = () => db.close();
    });
  }

  async function savePathStat(stat) {
    const db = await _openPathStatsDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(PATH_STATS_STORE, "readwrite");
      const store = tx.objectStore(PATH_STATS_STORE);
      const row = Object.assign({}, stat, {
        id: _pathStatKey(stat.peer_fp, stat.path_kind),
      });
      const req = store.put(row);
      req.onerror = () => reject(req.error || new Error("path stats write failed"));
      req.onsuccess = () => resolve(row);
      tx.oncomplete = () => db.close();
    });
  }

  function observePathResult(prev, result) {
    const stat = Object.assign(
      _defaultPathStat(result.peer_fp, result.path_kind),
      prev || {},
    );
    const bytes = Math.max(0, Number(result.bytes || 0));
    const elapsedMs = Math.max(1, Number(result.elapsed_ms || 1));
    const ok = result.ok !== false;
    const throughput = ok && bytes > 0 ? (bytes * 8 * 1000) / elapsedMs : 0;
    const oldBps = Number(stat.ewma_throughput_bps || 0);
    const oldFail = Number(stat.ewma_failure_rate || 0);
    stat.ewma_throughput_bps = oldBps <= 0
      ? throughput
      : ((1 - PATH_EWMA_ALPHA) * oldBps) + (PATH_EWMA_ALPHA * throughput);
    stat.ewma_failure_rate = ((1 - PATH_EWMA_ALPHA) * oldFail) + (PATH_EWMA_ALPHA * (ok ? 0 : 1));
    stat.samples = Number(stat.samples || 0) + 1;
    stat.last_used_ms = Date.now();
    return stat;
  }

  function _pathSupported(pathKind, localCaps, peerCaps) {
    const local = new Set(localCaps || browserTransportCapabilities());
    const peer = new Set(peerCaps || []);
    if (pathKind === "webtransport") {
      return !!window.WebTransport && local.has("webtransport_v1") && peer.has("webtransport_v1");
    }
    if (pathKind === "webrtc") {
      return !!window.RTCPeerConnection && local.has("webrtc_v1") && peer.has("webrtc_v1");
    }
    if (pathKind === "manual_webrtc") {
      return !!window.RTCPeerConnection && local.has("manual_signal_v1");
    }
    return false;
  }

  function pathScore(stat, pathKind) {
    const s = stat || _defaultPathStat("unknown", pathKind);
    const bps = Number(s.ewma_throughput_bps || 0);
    const failure = Math.min(1, Math.max(0, Number(s.ewma_failure_rate || 0)));
    const freshness = s.last_used_ms
      ? Math.max(0.55, Math.exp(-(Date.now() - Number(s.last_used_ms)) / (30 * 60 * 1000)))
      : 0.75;
    const baseline = pathKind === "webtransport" ? 900_000_000
      : pathKind === "webrtc" ? 450_000_000
      : 180_000_000;
    const learned = bps > 0 ? bps : baseline;
    return learned * freshness * (1 - PATH_FAILURE_PENALTY * failure);
  }

  function chooseTransportPath(opts) {
    opts = opts || {};
    const localCaps = opts.localCaps || browserTransportCapabilities();
    const peerCaps = opts.peerCaps || [];
    const statsByPath = opts.statsByPath || {};
    const candidates = ["webtransport", "webrtc", "manual_webrtc"]
      .filter((p) => _pathSupported(p, localCaps, peerCaps));
    if (!candidates.length) {
      return {
        path_kind: "unavailable",
        reason: "no shared browser transport",
        score: 0,
        candidates: [],
      };
    }
    const scored = candidates.map((path) => ({
      path_kind: path,
      score: pathScore(statsByPath[path], path),
      samples: Number((statsByPath[path] || {}).samples || 0),
    })).sort((a, b) => b.score - a.score || a.path_kind.localeCompare(b.path_kind));
    const epsilon = opts.epsilon == null ? PATH_EPSILON_BASE : Number(opts.epsilon);
    if (scored.length > 1 && Math.random() < epsilon) {
      const explore = scored.find((c) => c.samples === 0) || scored[scored.length - 1];
      return Object.assign({}, explore, {
        reason: "explore alternate path",
        candidates: scored,
      });
    }
    return Object.assign({}, scored[0], {
      reason: "best observed path",
      candidates: scored,
    });
  }

  async function openWebTransport(url) {
    if (!window.WebTransport) {
      throw new Error("WebTransport unavailable in this browser");
    }
    if (!/^https:\/\//i.test(String(url || ""))) {
      throw new Error("WebTransport requires https://");
    }
    const wt = new WebTransport(url);
    await wt.ready;
    return wt;
  }

  async function selectTransportForPeer(peerFp, peerCaps) {
    let rows = [];
    try {
      rows = await loadPathStats(peerFp);
    } catch {}
    const statsByPath = {};
    for (const row of rows) statsByPath[row.path_kind] = row;
    return chooseTransportPath({ peerCaps, statsByPath });
  }

