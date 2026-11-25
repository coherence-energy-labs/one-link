  // ── v0.10.3 first-pair nudge ──────────────────────────────────────
  // Show a "say hi" callout above the chat ONCE after a peer first
  // becomes pinned. Tracks shown-fingerprints in localStorage so the
  // nudge doesn't re-pop on subsequent visits or new pairings.
  const FIRST_PAIR_KEY = "one_link.first_pair_shown";

  function _firstPairShownSet() {
    try {
      const raw = localStorage.getItem(FIRST_PAIR_KEY) || "";
      return new Set(raw.split(",").filter(Boolean));
    } catch { return new Set(); }
  }
  function _markFirstPairShown(fp) {
    try {
      const cur = _firstPairShownSet();
      cur.add(fp);
      localStorage.setItem(FIRST_PAIR_KEY, [...cur].join(","));
    } catch {}
  }

  function maybeShowFirstPairNudge(fp) {
    if (!fp) return;
    if (_firstPairShownSet().has(fp)) return;
    _markFirstPairShown(fp);
    // Defer the render so the peer record has time to land in
    // state.peers via the next refreshPeers tick.
    setTimeout(() => renderFirstPairNudge(fp), 1200);
  }

  function renderFirstPairNudge(fp) {
    if (!state.selectedPeer) {
      // Auto-select the peer that just paired so the nudge feels
      // contextual rather than a stranger message.
      const peer = [...state.peers.values()]
        .find(p => p.fingerprint === fp);
      if (peer) selectPeer(peer.short_id);
    }
    const m = $("#messages");
    if (!m) return;
    const peer = [...state.peers.values()]
      .find(p => p.fingerprint === fp);
    const name = peer ? (peer.display_name || peer.hostname || peer.short_id) : "your new device";
    const wrap = el("div", "first-pair-nudge");
    wrap.appendChild(el("div", "fpn-icon", "👋"));
    const text = el("div", "fpn-text");
    text.appendChild(document.createTextNode("You're paired with "));
    text.appendChild(el("strong", "", name));
    text.appendChild(document.createTextNode(". Say hi to confirm the wires actually wire up."));
    wrap.appendChild(text);
    const btn = el("button", "", "Say hi");
    btn.onclick = () => {
      // Pre-fill the composer with a friendly first message.
      const input = $("#input");
      if (input) {
        input.value = "👋";
        input.focus();
        // Slight delay before pressing Send so the user SEES the
        // pre-fill rather than getting an instant flash.
        setTimeout(() => $("#btn-send")?.click(), 250);
      }
      wrap.remove();
    };
    wrap.appendChild(btn);
    // Insert before the messages list so it sits right under the
    // conversation header.
    m.insertBefore(wrap, m.firstChild);
    setTimeout(() => {
      // Auto-dismiss after 30s if untouched.
      wrap.style.transition = "opacity .4s ease, max-height .4s ease";
      wrap.style.opacity = "0";
      wrap.style.maxHeight = "0";
      setTimeout(() => wrap.remove(), 450);
    }, 30_000);
  }

  // ── v0.10.3 rich empty states ─────────────────────────────────────
  // Single helper so every list-empty case looks the same: a big
  // glyph, a heading, a one-sentence explanation. Reusable across
  // panes (Files, Folders, Activity, etc).
  function richEmpty(glyph, heading, body, ...children) {
    const wrap = el("div", "empty rich");
    wrap.appendChild(el("div", "rich-glyph", glyph));
    wrap.appendChild(el("h4", "", heading));
    wrap.appendChild(el("p", "", body));
    for (const c of children) {
      if (c) wrap.appendChild(c);
    }
    return wrap;
  }

  // ── Toasts ─────────────────────────────────────────────────────────
  const toast = (text, kind = "info", ttl = 3500) => {
    const t = el("div", `toast ${kind}`, text);
    $("#toasts").appendChild(t);
    // v0.6.3: return the element so callers (long-running uploads,
    // group sends) can remove it early when the operation completes.
    setTimeout(() => { t.style.opacity = 0; t.style.transition = "opacity .25s"; setTimeout(() => t.remove(), 280); }, ttl);
    return t;
  };

