  function aggregateActiveTransferStats() {
    // v0.21.x: split by direction so the header pill can say
    // "Receiving" for inbound transfers instead of always "Sending".
    // v0.21.x audit: also collect peer fingerprints per direction (so
    // the pill can name the device) AND skip stuck-at-0% rows that
    // haven't moved in >30s — they were dominating the pill as a
    // misleading "Sending 1 file 0%" with no actual progress.
    // 2026-06-04: also return the active transfer IDs so the pill's
    // new X cancel button can POST /api/transfers/{id}/cancel for
    // exactly the rows being shown. The cancel surface is the
    // primary fix for a misleading "Sending 1 file" pill the user
    // can't otherwise dismiss.
    //
    // Tightened the staleness window: an OFFERED transfer that
    // hasn't moved in 10s is functionally stalled (the peer either
    // isn't around or hasn't ack'd the offer); keep the lenient 30s
    // window only for ACTIVE rows that are genuinely mid-flight
    // but momentarily quiet (e.g. brief reconnect). Without this
    // split, an unanswered offer dominates the pill for 30 long
    // seconds — feels like a hang.
    const STALE_ACTIVE_NO_PROGRESS_MS  = 30_000;
    const STALE_OFFERED_NO_PROGRESS_MS = 10_000;
    const nowMs = Date.now();
    let count = 0, sendCount = 0, recvCount = 0;
    let bps = 0, sent = 0, total = 0;
    const sendPeerFps = new Set();
    const recvPeerFps = new Set();
    const activeIds = [];
    for (const t of state.transfers) {
      if (t.status !== "active" && t.status !== "offered") continue;
      const progressed = (t.progress_bytes || 0) > 0;
      const rate = rateForTransfer(t);
      const ageMs = nowMs - (t.updated_ms || nowMs);
      const staleWindow = t.status === "offered"
        ? STALE_OFFERED_NO_PROGRESS_MS
        : STALE_ACTIVE_NO_PROGRESS_MS;
      // Skip stuck rows: no bytes, no live rate, and the daemon
      // hasn't updated the row in the stale window for its status.
      if (!progressed && rate <= 0 && ageMs > staleWindow) continue;
      count += 1;
      if (t.id) activeIds.push(t.id);
      if (t.direction === "in") { recvCount += 1; if (t.peer_fp) recvPeerFps.add(t.peer_fp); }
      else { sendCount += 1; if (t.peer_fp) sendPeerFps.add(t.peer_fp); }
      bps += rate;
      sent += t.progress_bytes || 0;
      total += t.total_bytes || 0;
    }
    return { count, sendCount, recvCount, bps, sent, total, sendPeerFps, recvPeerFps, activeIds };
  }

  // Resolve a peer fingerprint to a display name (Computer 2 etc.).
  // Returns null when state.peers hasn't loaded yet so the caller can
  // gracefully drop the "to/from <name>" clause.
  function _peerLabelByFp(fp) {
    if (!fp || !state.peers) return null;
    const p = [...state.peers.values()].find(x => x.fingerprint === fp);
    if (!p) return null;
    return p.display_name || p.hostname || p.short_id || null;
  }
  function _activeTransferVerbLabel(sendCount, recvCount, sendPeerFps, recvPeerFps) {
    // ASCII separator only. The middle-dot (·) is a fragile unicode
    // separator the codebase bans in live status strings — a single
    // encoding slip renders it as "Â·" mojibake. A comma reads more
    // naturally between the two count clauses anyway.
    // Include the peer name when only ONE peer is on each side so the
    // pill answers "to/from whom?" at a glance ("Sending 1 file to
    // Computer 2"). Falls back to a bare count when multiple peers
    // are involved or the peer record hasn't loaded yet.
    const phrase = (verb, count, peerFps) => {
      const word = `${verb} ${count} file${count === 1 ? "" : "s"}`;
      const fps = peerFps ? [...peerFps] : [];
      if (fps.length === 1) {
        const who = _peerLabelByFp(fps[0]);
        if (who) {
          const prep = verb === "Sending" ? "to" : "from";
          return `${word} ${prep} ${who}`;
        }
      } else if (fps.length > 1) {
        const prep = verb === "Sending" ? "to" : "from";
        return `${word} ${prep} ${fps.length} devices`;
      }
      return word;
    };
    const parts = [];
    if (sendCount > 0) parts.push(phrase("Sending", sendCount, sendPeerFps));
    if (recvCount > 0) parts.push(phrase("Receiving", recvCount, recvPeerFps));
    return parts.join(", ") || "Transferring";
  }

  // v0.8.8: aggregate header pill renderer. Hidden when zero
  // transfers are active. Click body opens the Files pane (Sent tab)
  // so the user can drill in; the new X button cancels every active
  // outbound transfer being shown so the user is never trapped by a
  // stuck "Sending 1 file 0%" they have no way to dismiss.
  function renderTransferHeaderPill() {
    const pill = $("#transfer-pill");
    if (!pill) return;
    const stats = aggregateActiveTransferStats();
    const { count, sendCount, recvCount, bps, sent, total, activeIds } = stats;
    if (count === 0) {
      pill.style.display = "none";
      pill.innerHTML = "";
      return;
    }
    pill.style.display = "inline-flex";
    pill.innerHTML = "";
    pill.appendChild(el("span", "pill-spinner"));
    const label = _activeTransferVerbLabel(
      sendCount, recvCount, stats.sendPeerFps, stats.recvPeerFps,
    );
    const rate = bps > 0 ? ` · ${fmtMbps(bps)}` : "";
    const pct = total > 0 ? ` · ${Math.round((sent / total) * 100)}%` : "";
    const textEl = el("span", "pill-text", label + rate + pct);
    pill.appendChild(textEl);
    const moveVerb = recvCount > 0 && sendCount === 0 ? "received" : "moved";
    pill.title = `${fmtBytes(sent)} of ${fmtBytes(total)} ${moveVerb}${bps > 0 ? ` at ${fmtMbps(bps)}` : ""}. Click to open Files; ✕ to cancel.`;
    // Body click → open Files. The X cancel button below
    // .stopPropagation()s so it doesn't also trigger this.
    pill.onclick = () => {
      const filesBtn = document.querySelector('[data-pane="files"]');
      if (_phoneCannotShow(filesBtn)) return;
      filesBtn.click();
      state.filesMode = "sent";
      const sentBtn = document.querySelector('[data-files-mode="sent"]');
      if (sentBtn) sentBtn.click();
    };
    // 2026-06-04: X cancel button. Cancels every transfer the pill
    // is currently representing. Each cancel POST is idempotent on
    // the daemon (turns active/offered/queued/paused → failed with
    // error=cancelled by user), so racing the user's click with a
    // late completion event is safe. Hide the X immediately on
    // click to feel responsive, then issue the cancels in parallel
    // and refresh once at the end. The pill itself will disappear
    // on the next render cycle once the rows have transitioned to
    // 'failed' status — but we also call renderTransferHeaderPill
    // here to wipe it without waiting for the WS event so the user
    // gets instant feedback.
    if (activeIds && activeIds.length > 0) {
      const closeBtn = el("button", "pill-close");
      closeBtn.type = "button";
      closeBtn.setAttribute("aria-label", "Cancel this transfer");
      closeBtn.title = (
        activeIds.length === 1
          ? "Cancel this transfer"
          : `Cancel all ${activeIds.length} active transfers`
      );
      closeBtn.innerHTML = (
        '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" '
        + 'stroke="currentColor" stroke-width="3" stroke-linecap="round" '
        + 'aria-hidden="true">'
        + '<path d="M6 6l12 12M18 6L6 18"/></svg>'
      );
      closeBtn.onclick = async (ev) => {
        ev.stopPropagation();
        closeBtn.disabled = true;
        try {
          await Promise.all(activeIds.map((id) =>
            api.post(`/api/transfers/${encodeURIComponent(id)}/cancel`, {})
              .catch(() => null)
          ));
          // Clear local state for the cancelled rows so the pill
          // disappears without waiting for the WS round-trip.
          for (const id of activeIds) transferStore.markCancelledByUser(id);
          renderTransferHeaderPill();
          scheduleRenderMessages?.();
          toast(
            activeIds.length === 1
              ? "Transfer cancelled."
              : `Cancelled ${activeIds.length} transfers.`,
            "info", 3500,
          );
          // Fire a refresh so the canonical state catches up.
          refreshTransfers?.().catch(() => {});
        } finally {
          closeBtn.disabled = false;
        }
      };
      pill.appendChild(closeBtn);
    }
  }
  let _transferHeaderPillScheduled = false;
  function scheduleRenderTransferHeaderPill() {
    if (_transferHeaderPillScheduled) return;
    _transferHeaderPillScheduled = true;
    requestAnimationFrame(() => {
      _transferHeaderPillScheduled = false;
      renderTransferHeaderPill();
    });
  }
  // Refresh pill on a timer too - so the rate decays correctly
  // even if no transfer event arrives for several seconds.
  setInterval(() => {
    const pill = $("#transfer-pill");
    if (pill && pill.style.display !== "none") {
      renderTransferHeaderPill();
    }
  }, 1000);
  function statusKind(t) {
    if (!t) return "queued";
    if (t.status === "complete") return "sent";
    if (t.status === "failed")   return (t.metadata || {}).transient ? "paused" : "failed";
    if (t.status === "paused")   return "paused";
    if (t.status === "active" || t.status === "offered") return "sending";
    return "queued";
  }
  function statusGlyph(kind) {
    if (kind === "sent") return "✓";
    if (kind === "failed") return "✗";
    if (kind === "paused") return "⏸";
    if (kind === "sending") return "⏳";
    return "•";
  }

