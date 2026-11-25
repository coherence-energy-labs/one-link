  function _recordFrame(label, durationMs) {
    const buf = state.frameBudget?.[label];
    if (!buf) return;
    buf.push(durationMs);
    const cap = state.frameBudget.capacity || 200;
    if (buf.length > cap) buf.shift();
  }
  function _measure(label, fn) {
    const t0 = performance.now();
    try {
      return fn();
    } finally {
      _recordFrame(label, performance.now() - t0);
    }
  }
  async function _measureAsync(label, fn) {
    const t0 = performance.now();
    try {
      return await fn();
    } finally {
      _recordFrame(label, performance.now() - t0);
    }
  }
  // Convenience accessors for tests + debug:
  window.__oneLinkFrameBudget = () => {
    const out = {};
    for (const k of Object.keys(state.frameBudget)) {
      const buf = state.frameBudget[k];
      if (!Array.isArray(buf) || buf.length === 0) {
        out[k] = null; continue;
      }
      const sorted = [...buf].sort((a, b) => a - b);
      out[k] = {
        n: buf.length,
        mean: buf.reduce((a, b) => a + b, 0) / buf.length,
        p50: sorted[Math.floor(sorted.length * 0.5)],
        p95: sorted[Math.floor(sorted.length * 0.95)],
        p99: sorted[Math.floor(sorted.length * 0.99)],
        max: sorted[sorted.length - 1],
      };
    }
    return out;
  };

  // v0.14.0 - Predictive peer-switch prefetch (Markov chain).
  //
  // Frontier engine for conversation-switch latency: when the user
  // taps peer A, we want their last 50 messages already decoded into
  // memory. Instead of pulling everything for everyone (memory hog),
  // we learn which peers the user typically switches BETWEEN and
  // pre-warm the most likely next.
  //
  // Model: a sparse transition matrix M[from -> to -> count]. After
  // each conversation switch, M[prev_short -> new_short]++. Predict:
  // for the current conversation `from`, the next-most-likely peer
  // is argmax_{to} M[from][to] (with a Laplace-smoothed prior so
  // first-time peers can win). Persistence in localStorage:
  // serialized as JSON, capped at MARKOV_MAX_FROM_KEYS top-counted
  // sources to stay under ~4KB. LRU eviction by lowest total count.
  //
  // Total-cost discipline: zero network until the user actually
  // switches; the prefetch is a `requestIdleCallback`-deferred fetch
  // for the predicted peer's last 50 messages, swallowed silently
  // on failure. We never speculatively MARK as read. We never
  // tell peers anything about predictions. It's purely local.

  const MARKOV_KEY = "one_link.markov.peer_switch.v1";
  const MARKOV_MAX_FROM_KEYS = 32;     // ~32 sources -> ~32 columns
  const MARKOV_MAX_TO_PER_FROM = 8;    // 8 destinations each
  const MARKOV_PREFETCH_LIMIT = 50;    // last 50 msgs prefetched
  const MARKOV_PRIOR = 0.5;             // Laplace smoothing

  function _loadMarkov() {
    try {
      const raw = localStorage.getItem(MARKOV_KEY);
      if (!raw) return {};
      const j = JSON.parse(raw);
      return (j && typeof j === "object") ? j : {};
    } catch {
      return {};
    }
  }
  function _saveMarkov(m) {
    try {
      // Cap from-keys to top-N by total count; evict the rest.
      const totals = Object.entries(m).map(([from, ts]) => [
        from, Object.values(ts).reduce((a, b) => a + b, 0),
      ]);
      totals.sort((a, b) => b[1] - a[1]);
      const keep = new Set(totals.slice(0, MARKOV_MAX_FROM_KEYS).map(t => t[0]));
      const out = {};
      for (const [from, ts] of Object.entries(m)) {
        if (!keep.has(from)) continue;
        // Cap to-keys per from.
        const tsArr = Object.entries(ts);
        tsArr.sort((a, b) => b[1] - a[1]);
        out[from] = Object.fromEntries(tsArr.slice(0, MARKOV_MAX_TO_PER_FROM));
      }
      const json = JSON.stringify(out);
      // Hard guard: never let the matrix exceed 4KB persisted.
      if (json.length > 4096) {
        // Halve all counts (keeps ratios; trims footprint).
        for (const from of Object.keys(out)) {
          for (const to of Object.keys(out[from])) {
            out[from][to] = Math.max(1, Math.floor(out[from][to] / 2));
          }
        }
        localStorage.setItem(MARKOV_KEY, JSON.stringify(out));
      } else {
        localStorage.setItem(MARKOV_KEY, json);
      }
    } catch {
      // localStorage full or otherwise unavailable: silent.
    }
  }
  state.markov = _loadMarkov();
  state.lastSelectedShortId = null;

  // v0.14.2 - state.tier and the show-advanced toggle.
  // tier = "default" | "advanced". On phone: default-off, per-session
  // (resets on tab close - we deliberately don't persist). On desktop:
  // default-on, persists in localStorage so power users don't have to
  // re-enable on every reload.
  state.tier = "default";
  function _initTier() {
    const ff = document.documentElement.getAttribute("data-form-factor");
    if (ff === "desktop") {
      // Desktop: read persisted preference (default-on if unset).
      const saved = localStorage.getItem("one_link.show_advanced");
      const showAdv = saved == null ? true : saved === "1";
      _setShowAdvanced(showAdv, /*persist=*/true);
    } else {
      // Phone / tablet: always start in default tier per session.
      _setShowAdvanced(false, /*persist=*/false);
    }
  }
  function _setShowAdvanced(on, persist) {
    state.tier = on ? "advanced" : "default";
    document.documentElement.classList.toggle("show-advanced", on);
    const t = $("#set-show-advanced");
    if (t) t.checked = on;
    if (persist) {
      try { localStorage.setItem("one_link.show_advanced", on ? "1" : "0"); }
      catch {}
    }
  }
  _initTier();
  // Wire the toggle. Persist iff desktop (so phones stay per-session).
  $("#set-show-advanced")?.addEventListener("change", (ev) => {
    const ff = document.documentElement.getAttribute("data-form-factor");
    _setShowAdvanced(!!ev.target.checked, ff === "desktop");
  });

  // Per-pane "N advanced controls hidden. [Show]" hint helper.
  // Inject into a host element; counts the hidden [data-tier="advanced"]
  // descendants. Tapping the [Show] link flips the global toggle.
  function _attachAdvancedHint(hostSelector) {
    const host = document.querySelector(hostSelector);
    if (!host) return;
    if (host.querySelector(":scope > .advanced-hint")) return;
    const advanced = host.querySelectorAll('[data-tier="advanced"]');
    if (advanced.length === 0) return;
    const hint = el("p", "advanced-hint");
    const count = advanced.length;
    hint.appendChild(document.createTextNode(
      `${count} advanced control${count === 1 ? "" : "s"} hidden.`,
    ));
    const showLink = document.createElement("a");
    showLink.textContent = "Show";
    showLink.onclick = (ev) => {
      ev.preventDefault();
      _setShowAdvanced(true, false);
    };
    hint.appendChild(showLink);
    host.appendChild(hint);
  }

  // v0.14.3 - guard programmatic pane navigation. The transfer pill
  // and the mesh-panel "active" tile both call .click() on a
  // [data-pane="files"] button. On phone that button carries
  // .desktop-only and is hidden via display:none !important; firing
  // the click handler anyway would set state.activePane="files" and
  // refresh the Files list against an inert panel. Callers must
  // bail when this returns true.
  function _phoneCannotShow(paneBtn) {
    if (!paneBtn) return true;
    if (document.documentElement.getAttribute("data-form-factor") !== "phone") return false;
    return paneBtn.classList.contains("desktop-only");
  }

  function _recordSwitch(toShortId) {
    const from = state.lastSelectedShortId;
    if (!from || !toShortId || from === toShortId) {
      state.lastSelectedShortId = toShortId || from;
      return;
    }
    const m = state.markov;
    if (!m[from]) m[from] = {};
    m[from][toShortId] = (m[from][toShortId] || 0) + 1;
    state.lastSelectedShortId = toShortId;
    _saveMarkov(m);
  }

  function _predictNextPeerShort(currentShortId) {
    const m = state.markov;
    if (!currentShortId || !m[currentShortId]) return null;
    // Argmax over destinations (with Laplace smoothing implicit:
    // ties broken by lex order so it's deterministic).
    let best = null, bestCount = -Infinity;
    for (const [to, count] of Object.entries(m[currentShortId])) {
      const adj = count + MARKOV_PRIOR;
      if (adj > bestCount) { bestCount = adj; best = to; }
    }
    return best;
  }

  // Idle-time prefetch: fetch the predicted peer's last N messages
  // into a local cache. Cheap; no UI side-effects. Failure is
  // silent (the user might still switch there, just without warm
  // memory).
  state.peerMessageCache = state.peerMessageCache || new Map();
  function _prefetchPeerMessages(shortId) {
    if (!shortId) return;
    if (state.peerMessageCache.has(shortId)) return; // already warm
    const peer = state.peers.get(shortId);
    if (!peer || !peer.fingerprint) return;
    const fp = peer.fingerprint;
    const idle = window.requestIdleCallback || ((cb) => setTimeout(cb, 200));
    idle(async () => {
      try {
        const r = await api.get(
          `/api/messages?peer=${fp}&limit=${MARKOV_PREFETCH_LIMIT}`,
        );
        // Cap cache to 8 peers worth so we don't grow unbounded.
        if (state.peerMessageCache.size >= 8) {
          const oldest = state.peerMessageCache.keys().next().value;
          state.peerMessageCache.delete(oldest);
        }
        state.peerMessageCache.set(shortId, {
          messages: r.messages || [],
          fetchedAt: Date.now(),
        });
      } catch {
        // Silent: prediction was wrong / peer offline / network down.
      }
    });
  }

  // After every conversation switch, fire-and-forget a prefetch of
  // the next-most-likely peer based on the user's history.
  function _maybePrefetchNext(currentShortId) {
    const next = _predictNextPeerShort(currentShortId);
    if (next && next !== currentShortId) _prefetchPeerMessages(next);
  }

  // v0.14.1 - Last-conversation persistence. We persist the
  // currently-selected peer / group so opening the app boots
  // straight back into the user's last chat (no manual re-tap on
  // every reload). Stored under one_link.last_selection.v1; tiny
  // JSON, capped to a single record.
