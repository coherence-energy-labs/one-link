  // ── Attention center ───────────────────────────────────────────────
  // Small bell in the header that lights up when there's anything the
  // user should look at: an incoming file waiting accept, a send stuck
  // or held by the recipient, a real send failure. Hidden when the
  // list is empty so the header stays quiet — surfacing only what
  // needs attention is the whole point.
  function _fmtAge(ms) {
    const s = Math.max(1, Math.round((ms || 0) / 1000));
    if (s < 60) return `${s}s`;
    const m = Math.round(s / 60);
    if (m < 60) return `${m}m`;
    return `${Math.round(m / 60)}h`;
  }
  function _attentionKindIcon(kind) {
    if (kind === "pending_accept") return "↓";
    if (kind === "stuck_outbound") return "↑";
    if (kind === "awaiting_remote_ok") return "↑";
    if (kind === "failed_needs_action") return "!";
    return "•";
  }
  function _attentionKindHead(item) {
    const who = item.peer_label
      || (item.peer_fp ? item.peer_fp.slice(0, 8) : "Someone");
    const file = displayFileName(item.name || "a file");
    if (item.kind === "pending_accept") return `${who} → ${file}`;
    if (item.kind === "stuck_outbound") return `${file} → ${who} (stuck)`;
    if (item.kind === "awaiting_remote_ok") return `${file} → ${who} (waiting)`;
    if (item.kind === "failed_needs_action") return `${file} → ${who} (failed)`;
    return `${file} → ${who}`;
  }
  // Captured at refresh time so the popover can tick ages forward
  // without re-fetching: live_age = item.since_ms + (now - fetchedAt).
  let _attentionFetchedAtMs = 0;
  function _liveSinceMs(item) {
    return (item.since_ms || 0) + Math.max(0, Date.now() - _attentionFetchedAtMs);
  }
  function _renderAttentionItem(item) {
    if (item.kind === "overflow") {
      const row = el("div", "attention-item");
      row.style.opacity = ".7";
      row.appendChild(el("div", "ai-sub", item.summary || ""));
      return row;
    }
    const row = el("div", "attention-item");
    const head = el("div", "ai-head", _attentionKindHead(item));
    head.title = `${item.name || ""}`;
    row.appendChild(head);
    const ageMs = _liveSinceMs(item);
    const sub = el(
      "div", "ai-sub",
      `${item.summary || ""}${ageMs ? ` · ${_fmtAge(ageMs)} ago` : ""}`,
    );
    row.appendChild(sub);
    const actions = el("div", "ai-actions");
    const tid = item.transfer_id;
    const refresh = async () => { await refreshAttention(); };
    for (const a of (item.actions || [])) {
      if (a === "accept") {
        const b = el("button", "btn-accept", "Accept");
        b.onclick = async () => { await acceptFileOffer(tid, false); await refresh(); };
        actions.appendChild(b);
      } else if (a === "decline") {
        const b = el("button", null, "Decline");
        b.onclick = async () => { await declineFileOffer(tid, false); await refresh(); };
        actions.appendChild(b);
      } else if (a === "cancel") {
        const b = el("button", null, "Cancel send");
        b.onclick = async () => {
          try {
            await api.post(`/api/transfers/${encodeURIComponent(tid)}/cancel`, {});
            // Safety-net hint so a wrong-click isn't a dead-end.
            toast(
              "Cancelled. Re-send from the chat or Activity if you change your mind.",
              "info", 4500,
            );
          } catch (e) { toast(`Cancel failed: ${e}`, "error"); }
          await refresh();
        };
        actions.appendChild(b);
      } else if (a === "retry") {
        const b = el("button", null, "Retry");
        b.onclick = async () => {
          try {
            if (item.peer_fp) {
              await api.post(`/api/peers/${encodeURIComponent(item.peer_fp)}/resume`, {});
            } else {
              await api.post(`/api/transfers/${encodeURIComponent(tid)}/retry`, {});
            }
          } catch (e) { toast(`Retry failed: ${e}`, "error"); }
          await refresh();
        };
        actions.appendChild(b);
      } else if (a === "dismiss") {
        const b = el("button", null, "Dismiss");
        b.onclick = async () => {
          try { await api.post(`/api/transfers/${encodeURIComponent(tid)}/dismiss`, {}); }
          catch (e) { toast(`Dismiss failed: ${e}`, "error"); }
          await refresh();
        };
        actions.appendChild(b);
      }
    }
    row.appendChild(actions);
    return row;
  }
  // Track count between renders so we only pulse on a RISE — once.
  let _lastAttentionCount = 0;
  function _renderAttentionBell() {
    const bell = $("#attention-bell");
    if (!bell) return;
    const items = state.attentionItems || [];
    if (items.length === 0) {
      bell.style.display = "none";
      const pop = $("#attention-popover");
      if (pop) pop.style.display = "none";
      _lastAttentionCount = 0;
      return;
    }
    bell.style.display = "inline-flex";
    // Proper notification-bell SVG (Feather/Lucide shape) — instantly
    // recognisable as "notifications" across every app the user has
    // ever used. Beats the prior warning ⚠ glyph which read as "error".
    bell.innerHTML = (
      '<span class="bell-glyph"><svg viewBox="0 0 24 24" width="14" '
      + 'height="14" fill="none" stroke="currentColor" stroke-width="2.2" '
      + 'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
      + '<path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/>'
      + '<path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg></span>'
      + `<span class="bell-count">${items.length}</span>`
    );
    if (items.length > _lastAttentionCount) {
      bell.classList.remove("pulse");
      void bell.offsetWidth;  // force reflow so the animation restarts
      bell.classList.add("pulse");
    }
    _lastAttentionCount = items.length;
  }
  function _renderAttentionPopover() {
    const pop = $("#attention-popover");
    if (!pop) return;
    const items = state.attentionItems || [];
    pop.innerHTML = "";
    if (items.length === 0) {
      pop.appendChild(el("div", "attention-empty", "Nothing needs attention."));
      return;
    }
    for (const item of items) pop.appendChild(_renderAttentionItem(item));
  }
  function _toggleAttentionPopover() {
    const pop = $("#attention-popover");
    if (!pop) return;
    const open = pop.style.display !== "none";
    if (open) { pop.style.display = "none"; return; }
    _renderAttentionPopover();
    pop.style.display = "block";
  }
  async function refreshAttention() {
    try {
      const r = await api.get("/api/transfers/attention");
      state.attentionItems = r.items || [];
    } catch (_e) {
      state.attentionItems = [];
    }
    _attentionFetchedAtMs = Date.now();
    _renderAttentionBell();
    const pop = $("#attention-popover");
    if (pop && pop.style.display !== "none") _renderAttentionPopover();
  }
  // Wire the bell click + a11y once at boot.
  document.addEventListener("DOMContentLoaded", () => {
    const bell = $("#attention-bell");
    if (bell) bell.onclick = _toggleAttentionPopover;
    // Close popover on outside click.
    document.addEventListener("click", (ev) => {
      const pop = $("#attention-popover");
      if (!pop || pop.style.display === "none") return;
      if (pop.contains(ev.target)) return;
      if (bell && bell.contains(ev.target)) return;
      pop.style.display = "none";
    });
    // Esc closes the popover + returns focus to the bell — standard
    // dismissable-overlay a11y. Enter/Space on the bell already
    // triggers click (native <button> behaviour).
    document.addEventListener("keydown", (ev) => {
      if (ev.key !== "Escape") return;
      const pop = $("#attention-popover");
      if (!pop || pop.style.display === "none") return;
      pop.style.display = "none";
      if (bell) bell.focus();
    });
  });
  // Periodic refresh in case a WS event is missed.
  setInterval(() => { refreshAttention().catch(()=>{}); }, 15_000);
  // Tab back into focus or becomes visible → user expects fresh state.
  // (15s heartbeat alone can show a stale "5s ago" right after a 2-min
  // tab-switch.)
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) refreshAttention().catch(()=>{});
  });
  window.addEventListener("focus", () => refreshAttention().catch(()=>{}));
  // Live age tick — re-render the popover every 5s while it's open so
  // "5s ago" turns into "10s ago" without re-hitting the server.
  setInterval(() => {
    const pop = $("#attention-popover");
    if (pop && pop.style.display !== "none") _renderAttentionPopover();
  }, 5_000);
  // Coalesce burst transfer events into a single refresh per tick.
  let _attentionRefreshScheduled = false;
  function scheduleAttentionRefresh() {
    if (_attentionRefreshScheduled) return;
    _attentionRefreshScheduled = true;
    setTimeout(() => {
      _attentionRefreshScheduled = false;
      refreshAttention().catch(()=>{});
    }, 300);
  }

