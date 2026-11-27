  // T3-Z: the O(1) (direction|blob) -> transfer index is owned by
  // transferStore, next to the by-id map it is derived from.
  function _rebuildTransferByDirBlob() {
    transferStore.rebuildDirBlobIndex();
  }
  function _trackTransferIndex(t) {
    // Incremental update path for the WS-event handler. Avoids a
    // full rebuild on every transfer event.
    transferStore.trackDirBlob(t);
  }
  function transferForMessage(msg) {
    const blob = (msg.blob || "").toLowerCase();
    if (!blob) return null;
    if (!state.transferByDirBlob) _rebuildTransferByDirBlob();
    return state.transferByDirBlob.get(`${msg.dir}|${blob}`) || null;
  }

  function statusLabel(t, fallback) {
    if (!t) return fallback;
    const meta = t.metadata || {};
    const inbound = t.direction === "in";
    // Skip display_state / doctor.label short-circuits for inbound
    // non-terminal transfers — otherwise the transfer doctor's
    // sender-oriented copy ("Sending…") would override the
    // direction-aware "Receiving…" labels below. Outbound + terminal
    // states keep using the doctor's enriched label as before.
    const nonTerminalInbound = inbound && ["queued", "offered", "active", "paused"].includes(t.status);
    if (t.display_state && !nonTerminalInbound) return t.display_state;
    if (meta.doctor?.label && !nonTerminalInbound) return meta.doctor.label;
    const stateName = meta.delivery_state || "";
    // 2026-05-22 audit Batch AA: short-circuit the empty-file edge.
    // Without this, total_bytes === 0 makes progress_pct = NaN ->
    // the label sticks at "Sending… 0%" indefinitely. The daemon
    // emits status=complete with progress_bytes=0/total_bytes=0 for
    // empty files; the active-status label needs to handle the
    // pre-complete pulse cleanly.
    const isEmpty = (t.total_bytes === 0 || t.size === 0);
    // v0.21.x: direction-aware copy. An INBOUND transfer (the peer is
    // sending TO us) must read "Receiving…", never "Sending…". Only
    // the terminal "complete" state was direction-aware before, so a
    // file the receiver was pulling showed "Sending… 42%" — confusing
    // and wrong. ``inbound`` drives every non-terminal label too.
    const actVerb = inbound ? "Receiving" : "Sending";
    if (t.status === "queued") {
      if (stateName === "resuming") return "Resuming";
      return inbound
        ? "Waiting for them to come back online"
        : "Will send when they're back online";
    }
    if (t.status === "offered") {
      if (isEmpty) return inbound ? "Receiving empty file" : "Sending empty file";
      return inbound ? "Receiving…" : "Sending…";
    }
    if (t.status === "active") {
      if (isEmpty) return inbound ? "Receiving empty file" : "Sending empty file";
      return `${actVerb}… ${Math.round(t.progress_pct || 0)}%`;
    }
    if (t.status === "complete") {
      if (isEmpty) return inbound ? "Empty file received" : "Empty file sent";
      return inbound ? "Received" : "Done";
    }
    if (t.status === "paused") {
      if (stateName === "resuming") return "Resuming";
      return inbound
        ? "Paused. Will resume when they're back."
        : "Paused. Will retry when they're back.";
    }
    if (t.status === "failed") {
      if (stateName === "sent_unconfirmed") {
        return "Sent · final integrity unconfirmed by older device";
      }
      return meta.transient ? "Will retry when they're back online" : "Needs attention";
    }
    return t.status || fallback;
  }

  // v0.8.8: per-transfer EWMA rate tracker. Each `transfer` WS event
  // is a snapshot - by diffing progress_bytes across events we get
  // bytes/sec without any extra wire data. transferStore owns the
  // tracker and its EWMA (alpha=0.4), which smooths out chunk-by-chunk
  // burstiness without going stale on slow links. Reset on terminal
  // status so the next transfer for the same id (e.g. retry after
  // pause) starts clean.
  function updateTransferRate(t) {
    if (!t || !t.id) return;
    const terminal = t.status === "complete" || t.status === "failed";
    if (terminal) {
      transferStore.forgetRate(t.id);
      return;
    }
    transferStore.sampleRate(t);
  }
  function rateForTransfer(t) {
    if (!t) return 0;
    const r = state.transferRates.get(t.id);
    if (!r) return 0;
    // Decay if no event for >3s - peer probably stalled. Avoids
    // showing a stale "14 MB/s" forever on a frozen transfer.
    const age = (Date.now() - (r.lastTs || 0)) / 1000;
    if (age > 3) return 0;
    return r.bps || 0;
  }
  function transferRouteLabel(route) {
    const r = String(route || "").toLowerCase();
    if (r === "lan" || r === "wifi" || r === "wifi_direct") return "Wi-Fi direct";
    if (r === "ethernet") return "Ethernet direct";
    if (r === "relay" || r === "rendezvous") return "Relay";
    if (r === "local_cache" || r === "known") return "Known chunks";
    if (r) return r.replace(/_/g, " ");
    return "Best available";
  }
  function transferAutopilotFacts(t, kind) {
    if (!t) return [];
    const truth = t.autopilot_truth || {};
    if (Array.isArray(truth.facts) && truth.facts.length) {
      return [...new Set(truth.facts.filter(Boolean))].slice(0, 7);
    }
    const meta = t.metadata || {};
    const plan = meta.autopilot_plan || {};
    const fabricTruth = meta.fabric_plan?.route_truth || {};
    const perf = meta.performance_summary || {};
    const assist = meta.swarm_assist || {};
    const facts = [];
    const liveBps = rateForTransfer(t);
    const doneBps = Number(perf.effective_mbps || 0) > 0
      ? (Number(perf.effective_mbps) * 1_000_000) / 8
      : 0;
    const displayBps = liveBps > 0 ? liveBps : doneBps;
    if (displayBps > 0) {
      // v0.21.x: direction-aware rate verb. Inbound mid-flight reads
      // "Receiving at", not "Sending at".
      const rateVerb = kind === "sent"
        ? "Finished at"
        : (t.direction === "in" ? "Receiving at" : "Sending at");
      facts.push(`${rateVerb} ${fmtMbps(displayBps)}`);
    }

    const progressBytes = Number(t.progress_bytes || 0);
    const totalBytes = Number(t.total_bytes || 0);
    const skippedBytes = Number(perf.skipped_bytes || meta.skipped_bytes || 0);
    const savedBytes = Number(perf.saved_bytes || meta.saved_bytes || assist.assisted_bytes || 0);
    let savings = Number(perf.bandwidth_savings_ratio || plan.estimated_savings_ratio || meta.bandwidth_savings_ratio || 0);
    if (!savings && totalBytes > 0 && (skippedBytes > 0 || savedBytes > 0)) {
      savings = Math.min(1, Math.max(0, (skippedBytes + savedBytes) / totalBytes));
    }
    if (savings > 0.01) {
      facts.push(`${Math.round(savings * 100)}% already known`);
      facts.push("Only sent missing pieces");
    }

    const frame = String(perf.frame_kind || plan.frame_kind || meta.frame_kind || "").toLowerCase();
    if (frame.includes("binary") || meta.binary_frame === true) {
      facts.push("Using fast binary path");
    }
    if (kind === "paused" || t.status === "queued" || meta.delivery_state === "resuming" || meta.transient) {
      facts.push("Resuming automatically");
    }
    if (assist && Number(assist.pulled || 0) > 0) {
      const pulled = Number(assist.pulled || 0);
      const sourceCount = Number(assist.source_count || Object.keys(assist.sources || {}).length || 1);
      facts.push(`Pulled ${pulled} chunk${pulled === 1 ? "" : "s"} from ${sourceCount} trusted device${sourceCount === 1 ? "" : "s"}`);
    }
    const route = fabricTruth.kind || perf.route || plan.route || meta.route || (assist.strategy === "multi_source_chunk_pull" ? "local_cache" : "");
    if (route) {
      const renderedRoute = fabricTruth.kind ? route : transferRouteLabel(route);
      facts.push(`Route: ${renderedRoute}`);
    }
    if (progressBytes > 0 && totalBytes > 0 && progressBytes < totalBytes && kind !== "sent") {
      facts.push("Resuming automatically");
    }
    return [...new Set(facts)].slice(0, 6);
  }
  function renderTransferFacts(t, kind) {
    const facts = transferAutopilotFacts(t, kind);
    if (!facts.length) return null;
    const wrap = el("div", "transfer-facts");
    for (const fact of facts) {
      wrap.appendChild(el("span", "transfer-fact", fact));
    }
    return wrap;
  }
  function renderTransferFactsCollapsed(t, kind) {
    // Chat-bubble + transfer-pane variant: pills are useful for
    // ops + debugging but visually busy on every message. Wrap them
    // in <details> so the headline (size + status) stays clean and
    // the user opts in to the detail pills when they want them.
    const facts = renderTransferFacts(t, kind);
    if (!facts) return null;
    const details = document.createElement("details");
    details.className = "transfer-facts-collapsed";
    const summary = document.createElement("summary");
    summary.textContent = "Details";
    details.appendChild(summary);
    details.appendChild(facts);
    return details;
  }
  function _fileDetailRow(key, value) {
    const row = el("div", "file-detail-row");
    row.appendChild(el("span", "k", key));
    row.appendChild(el("span", "v", value || "-"));
    return row;
  }
  function _fileDiagnosticPayload(msg, t, access, kind) {
    return {
      file: msg.name || "file",
      size: fmtBytes(msg.size || t?.total_bytes || 0),
      status: statusLabel(t, kind === "sent" ? "Done" : kind),
      direction: msg.dir === "out" ? "sent" : "received",
      type: isImageName(msg.name || "") ? "image" : (isAudioName(msg.name || "") ? "audio" : "file"),
      preview_route: access.route,
      source: access.source,
      problem: access.problem || "",
      transfer_id: t?.id || "",
    };
  }
  function _filePreviewSourceLabel(msg, t) {
    if (msg.dir === "in") return "Received file on this computer";
    if (msg.dir === "out" && t?.id) return "Sender copy from transfer ledger";
    if (msg.dir === "out") return "Sender browser cache";
    return "Local file endpoint";
  }
  function renderFileBubbleDetails(msg, t, kind) {
    const details = document.createElement("details");
    details.className = "transfer-facts-collapsed file-bubble-details";
    const summary = document.createElement("summary");
    summary.textContent = "Details";
    details.appendChild(summary);
    const access = fileAccessInfoForMessage(msg, t);

    const rows = el("div", "file-detail-rows");
    rows.appendChild(_fileDetailRow("Status", statusLabel(t, kind === "sent" ? "Done" : kind)));
    rows.appendChild(_fileDetailRow("Direction", msg.dir === "out" ? "Sent from this computer" : "Received on this computer"));
    rows.appendChild(_fileDetailRow("Size", fmtBytes(msg.size || t?.total_bytes || 0)));
    rows.appendChild(_fileDetailRow("Type", isImageName(msg.name || "") ? "Image" : (isAudioName(msg.name || "") ? "Audio" : "File")));
    rows.appendChild(_fileDetailRow("Preview", _filePreviewSourceLabel(msg, t)));
    rows.appendChild(_fileDetailRow("Open route", access.route));
    rows.appendChild(_fileDetailRow("Source", access.source));
    rows.appendChild(_fileDetailRow("Preview route", access.url ? "Ready on this device" : "Unavailable on this device"));
    if (access.problem) rows.appendChild(_fileDetailRow("Needs", access.problem));
    if (t?.id) rows.appendChild(_fileDetailRow("Transfer", String(t.id).slice(0, 12)));
    details.appendChild(rows);

    const actions = el("div", "actions");
    const diagnostic = _fileDiagnosticPayload(msg, t, access, kind);
    if (access.url) {
      const open = el("a", "", "Open");
      open.href = access.url;
      open.target = "_blank";
      open.rel = "noopener";
      actions.appendChild(open);
      const save = el("a", "", "Save a copy");
      save.href = access.url;
      save.setAttribute("download", msg.name || "file");
      actions.appendChild(save);
    } else {
      const unavailable = el("span", "hint", "Preview not available on this side");
      actions.appendChild(unavailable);
    }
    const copy = el("button", "", "Copy file details");
    copy.type = "button";
    copy.onclick = (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      copyToClipboard(JSON.stringify(diagnostic, null, 2), "file details");
    };
    actions.appendChild(copy);
    details.appendChild(actions);

    const facts = renderTransferFacts(t, kind);
    if (facts) details.appendChild(facts);
    return details;
  }
  function renderImagePreviewFallback(msg, url, reason, onRetry) {
    const wrap = el("div", "file-preview-fallback");
    wrap.appendChild(el("div", "title", "Image preview unavailable"));
    wrap.appendChild(el("div", "hint",
      reason || "Preview unavailable. The transfer finished, but this device could not load the image preview from its local file endpoint."));
    const rows = el("div", "file-detail-rows");
    rows.appendChild(_fileDetailRow("File", msg.name || "image"));
    rows.appendChild(_fileDetailRow("Size", fmtBytes(msg.size || 0)));
    rows.appendChild(_fileDetailRow("Preview route", url ? "Local browser route" : "No preview route"));
    rows.appendChild(_fileDetailRow("Why", reason || "The local route did not return image bytes."));
    wrap.appendChild(rows);
    const actions = el("div", "actions");
    if (url) {
      const open = el("a", "", "Open");
      open.href = url;
      open.target = "_blank";
      open.rel = "noopener";
      actions.appendChild(open);
      const save = el("a", "", "Save a copy");
      save.href = url;
      save.setAttribute("download", msg.name || "image");
      actions.appendChild(save);
    }
    if (typeof onRetry === "function") {
      const retry = el("button", "", "Retry preview");
      retry.type = "button";
      retry.onclick = (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        onRetry();
      };
      actions.appendChild(retry);
    }
    if (actions.childNodes.length) wrap.appendChild(actions);
    return wrap;
  }
  function attachImagePreviewFallback(img, meta, msg, url, reason, altUrl) {
    img.onerror = () => {
      // Try the alternate route once (e.g. by-name after by-blob, or
      // vice-versa) before declaring the preview unavailable.
      if (altUrl && altUrl !== url && img.dataset.triedAlt !== "1") {
        img.dataset.triedAlt = "1";
        img.src = altUrl;
        return;
      }
      if (img.dataset.failedPreview === "1") return;
      img.dataset.failedPreview = "1";
      const finalUrl = img.dataset.triedAlt === "1" ? altUrl : url;
      const retry = () => {
        fallback.remove();
        img.dataset.failedPreview = "0";
        img.src = `${finalUrl}${finalUrl.includes("?") ? "&" : "?"}retry=${Date.now()}`;
        meta.appendChild(img);
      };
      const fallback = renderImagePreviewFallback(msg, finalUrl, reason, retry);
      img.remove();
      meta.appendChild(fallback);
      _forceMessagesBottomNowAndAfter(800);
    };
  }
  function transferCommandMetrics(t) {
    if (!t) return [];
    const truth = t.autopilot_truth || {};
    const meta = t.metadata || {};
    const perf = meta.performance_summary || {};
    const report = meta.transfer_report || {};
    const fabricTruth = meta.fabric_plan?.route_truth || {};
    const liveBps = rateForTransfer(t);
    const speedMbps = liveBps > 0
      ? (liveBps * 8) / 1_000_000
      : Number(truth.speed_mbps || perf.effective_mbps || 0);
    const wireMbps = Number(truth.wire_mbps || perf.wire_mbps || 0);
    const knownPct = Number(truth.known_pct || 0);
    const savedBytes = Number(
      truth.saved_bytes || perf.saved_bytes || report.saved_bytes ||
      meta.saved_bytes || meta.swarm_assist?.assisted_bytes || 0
    );
    const assist = meta.swarm_assist || {};
    const swarmSources = Number(assist.source_count || Object.keys(assist.sources || {}).length || 0);
    const swarmHealed = Number(assist.healed || 0);
    const wireBytes = Number(
      truth.wire_bytes || report.wire_bytes_sent || t.wire_bytes || 0
    );
    const route = truth.route_label || fabricTruth.kind || transferRouteLabel(
      truth.route || perf.route || meta.autopilot_plan?.route || meta.route
    );
    const rows = [];
    if (speedMbps > 0) rows.push({ label: "effective", value: `${speedMbps >= 100 ? speedMbps.toFixed(0) : speedMbps.toFixed(1)} Mbps` });
    if (wireMbps > 0) rows.push({ label: "wire", value: `${wireMbps >= 100 ? wireMbps.toFixed(0) : wireMbps.toFixed(1)} Mbps` });
    if (knownPct > 0) rows.push({ label: "already known", value: `${knownPct >= 10 ? knownPct.toFixed(0) : knownPct.toFixed(1)}%` });
    if (savedBytes > 0) rows.push({ label: "avoided", value: fmtBytes(savedBytes) });
    if (swarmSources > 0) rows.push({ label: "sources", value: String(swarmSources) });
    if (swarmHealed > 0) rows.push({ label: "healed", value: String(swarmHealed) });
    if (wireBytes > 0) rows.push({ label: "sent over wire", value: fmtBytes(wireBytes) });
    if (route && route !== "Best available") rows.push({ label: "route", value: route });
    if (truth.fast_path_label) rows.push({ label: "path", value: truth.fast_path_label });
    if (truth.automatic && truth.self_healing_action && !["none", "continue", "observe"].includes(truth.self_healing_action)) {
      rows.push({ label: "self-healing", value: truth.self_healing_action.replace(/_/g, " ") });
    }
    return rows.slice(0, 8);
  }
  function renderTransferCommandCenter(t) {
    const metrics = transferCommandMetrics(t);
    if (!metrics.length) return null;
    const wrap = el("div", "transfer-command");
    wrap.title = "One Link transfer autopilot: effective speed, actual wire cost, savings, route, and self-healing state.";
    for (const m of metrics) {
      const card = el("div", "tc-metric");
      card.appendChild(el("div", "tc-value", m.value));
      card.appendChild(el("div", "tc-label", m.label));
      wrap.appendChild(card);
    }
    return wrap;
  }
  function renderPrimaryTransferSummary(t) {
    const metrics = transferCommandMetrics(t);
    const facts = transferAutopilotFacts(t, statusKind(t));
    const speed = metrics.find(m => m.label === "effective")?.value || "";
    const known = metrics.find(m => m.label === "already known")?.value || "";
    const route = metrics.find(m => m.label === "route")?.value || "";
    const bits = [];
    if (speed) bits.push({ text: speed, strong: true });
    if (known) bits.push({ text: `${known} already known` });
    if (route) bits.push({ text: route });
    if (!bits.length && facts.length) bits.push({ text: facts[0] });
    if (!bits.length) return null;
    const out = el("div", "sent-summary");
    bits.forEach((bit, idx) => {
      if (idx) out.appendChild(document.createTextNode(" - "));
      out.appendChild(el(bit.strong ? "strong" : "span", null, bit.text));
    });
    return out;
  }
  function renderTransferDetails(t) {
    const command = renderTransferCommandCenter(t);
    const facts = renderTransferFacts(t, statusKind(t));
    if (!command && !facts) return null;
    const details = document.createElement("details");
    details.className = "transfer-details";
    const summary = document.createElement("summary");
    summary.textContent = "Details";
    details.appendChild(summary);
    if (command) details.appendChild(command);
    if (facts) details.appendChild(facts);
    return details;
  }
