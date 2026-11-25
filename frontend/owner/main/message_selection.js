  // ── Multi-select + forward (v0.10.1) ──────────────────────────────
  // Right-click any message → enters selection mode + selects it.
  // Click any message in selection mode → toggle. Top action bar
  // surfaces Forward / Copy / Pin / Delete / Cancel.
  state.selecting = false;
  state.selectedMessageIds = new Set();

  function enterSelection(seedMsgId) {
    state.selecting = true;
    state.selectedMessageIds = new Set();
    if (seedMsgId) state.selectedMessageIds.add(seedMsgId);
    document.querySelector("#messages")?.classList.add("selecting");
    renderSelectionBar();
    paintSelectionMarks();
  }
  function exitSelection() {
    state.selecting = false;
    state.selectedMessageIds.clear();
    document.querySelector("#messages")?.classList.remove("selecting");
    $("#select-bar").style.display = "none";
    paintSelectionMarks();
  }
  function toggleMessageSelected(msgId) {
    if (!state.selecting) return;
    if (state.selectedMessageIds.has(msgId)) {
      state.selectedMessageIds.delete(msgId);
    } else {
      state.selectedMessageIds.add(msgId);
    }
    if (state.selectedMessageIds.size === 0) {
      exitSelection();
      return;
    }
    renderSelectionBar();
    paintSelectionMarks();
  }
  function paintSelectionMarks() {
    document.querySelectorAll("#messages .msg").forEach((b) => {
      const id = b.dataset.msgId;
      b.classList.toggle("selected", !!id && state.selectedMessageIds.has(id));
    });
  }
  function renderSelectionBar() {
    const bar = $("#select-bar");
    if (!bar) return;
    const n = state.selectedMessageIds.size;
    if (n === 0) {
      bar.style.display = "none";
      return;
    }
    bar.style.display = "flex";
    $("#sb-count").textContent =
      `${n} selected`;
    // Disable Delete unless ALL selected are our own messages within
    // the 5-min edit cooldown (mirrors per-bubble Delete eligibility).
    const allOursAndRecent = _selectedMessages().every((m) => {
      if (m.dir !== "out" || m.deleted) return false;
      return Date.now() - (m.ts || 0) < 5 * 60 * 1000;
    });
    $("#sb-delete").disabled = !allOursAndRecent;
    $("#sb-delete").style.opacity = allOursAndRecent ? "1" : ".4";
  }
  function _selectedMessages() {
    // Resolves the set of msg_ids back to message records from
    // state.messages OR state.groupMessages depending on context.
    const all = state.selectedGroup
      ? (state.groupMessages || [])
      : (state.messages || []);
    const ids = state.selectedMessageIds;
    return all.filter((m) => ids.has(m.id));
  }

  function bindSelectionToBubble(b, msg) {
    // Right-click enters selection mode + adds this msg.
    b.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      if (!state.selecting) {
        enterSelection(msg.id);
      } else {
        toggleMessageSelected(msg.id);
      }
    });
    // While selecting, plain click toggles.
    b.addEventListener("click", (e) => {
      if (!state.selecting) return;
      // Don't intercept clicks on inline links inside the bubble.
      if (e.target.tagName === "A") return;
      e.stopPropagation();
      toggleMessageSelected(msg.id);
    });
  }

  // Action handlers.
  async function selectionCopy() {
    const lines = _selectedMessages()
      .sort((a, b) => (a.ts || 0) - (b.ts || 0))
      .map((m) => m.body || "");
    const text = lines.join("\n");
    try {
      await navigator.clipboard.writeText(text);
      toast(`Copied ${lines.length} message${lines.length === 1 ? "" : "s"}`,
            "good", 2000);
    } catch (e) {
      toast(`Copy didn't work: ${e.message || e}`, "bad");
    }
    exitSelection();
  }
  async function selectionDelete() {
    const msgs = _selectedMessages();
    if (msgs.length === 0) return;
    if (!confirm(`Delete ${msgs.length} message${msgs.length === 1 ? "" : "s"}?\n\nThis tombstones them locally and (when reachable) on the recipient's device.`)) return;
    let ok = 0, fail = 0;
    for (const m of msgs) {
      try {
        await api.post(`/api/messages/${encodeURIComponent(m.id)}/delete`, {});
        ok += 1;
      } catch { fail += 1; }
    }
    toast(
      fail === 0 ? `Deleted ${ok}.` : `Deleted ${ok}, ${fail} failed.`,
      fail === 0 ? "good" : "warn",
    );
    exitSelection();
    await loadHistory();
  }
  async function selectionPin() {
    const msgs = _selectedMessages();
    if (msgs.length === 0) return;
    let ok = 0;
    for (const m of msgs) {
      try {
        if (!isPinned(m)) {
          togglePin(m);
          ok += 1;
        }
      } catch {}
    }
    toast(`Pinned ${ok} message${ok === 1 ? "" : "s"}.`, "good", 2000);
    exitSelection();
  }

  // ── Forward picker ────────────────────────────────────────────────
  function openForwardPicker() {
    const msgs = _selectedMessages();
    if (msgs.length === 0) return;
    $("#forward-summary").textContent =
      `Choose where to send ${msgs.length} message${msgs.length === 1 ? "" : "s"}.`;
    $("#forward-search").value = "";
    renderForwardTargets("");
    $("#forward-backdrop").classList.add("show");
    setTimeout(() => $("#forward-search").focus(), 30);
  }
  function closeForwardPicker() {
    $("#forward-backdrop").classList.remove("show");
  }
  function renderForwardTargets(filter) {
    const list = $("#forward-list");
    list.innerHTML = "";
    const f = (filter || "").toLowerCase();
    // Pinned peers first, then groups.
    const peers = [...state.peers.values()]
      .filter((p) => p.trust === "pinned")
      .filter((p) => {
        if (!f) return true;
        const name = (p.display_name || p.hostname || p.short_id).toLowerCase();
        return name.includes(f);
      });
    const groups = [...(state.groups?.values?.() || [])]
      .filter((g) => !f || (g.name || "").toLowerCase().includes(f));
    if (peers.length === 0 && groups.length === 0) {
      list.appendChild(el("div", "empty", "Nothing matches. Try fewer words."));
      return;
    }
    for (const p of peers) {
      const row = el("div", "forward-row");
      const init = (p.display_name || p.hostname || p.short_id || "?")[0];
      row.appendChild(el("div", "fr-icon", init.toUpperCase()));
      row.appendChild(el("div", "fr-name",
        p.display_name || p.hostname || p.short_id));
      row.appendChild(el("div", "fr-kind", "Device"));
      row.onclick = () => forwardTo({ peer_short_id: p.short_id });
      list.appendChild(row);
    }
    for (const g of groups) {
      const row = el("div", "forward-row");
      row.appendChild(el("div", "fr-icon", "👥"));
      row.appendChild(el("div", "fr-name", g.name || "(unnamed group)"));
      row.appendChild(el("div", "fr-kind", "Group"));
      row.onclick = () => forwardTo({ group_id: g.group_id });
      list.appendChild(row);
    }
  }
  async function forwardTo(target) {
    const msgs = _selectedMessages()
      .sort((a, b) => (a.ts || 0) - (b.ts || 0));
    if (msgs.length === 0) return;
    closeForwardPicker();
    const sending = toast(`Forwarding ${msgs.length}…`, "info", 30000);
    let ok = 0, fail = 0;
    for (const m of msgs) {
      const body = m.body || "";
      // Prefix marks the message as a forward to the receiver.
      // Recipients see the indent + arrow; useful even without a
      // dedicated wire frame.
      const forwardedBody = `↪ Forwarded\n${body}`;
      try {
        if (target.group_id) {
          await api.post(
            `/api/groups/${target.group_id}/send`,
            { body: forwardedBody },
          );
        } else if (target.peer_short_id) {
          await api.post("/api/send", {
            peer: target.peer_short_id, body: forwardedBody,
          });
        }
        ok += 1;
      } catch {
        fail += 1;
      }
    }
    sending?.remove?.();
    toast(
      fail === 0 ? `Forwarded ${ok}.` : `Forwarded ${ok}, ${fail} failed.`,
      fail === 0 ? "good" : "warn",
    );
    exitSelection();
  }

  // Wire toolbar buttons.
  $("#sb-cancel")?.addEventListener("click", exitSelection);
  $("#sb-copy")?.addEventListener("click", selectionCopy);
  $("#sb-pin")?.addEventListener("click", selectionPin);
  $("#sb-delete")?.addEventListener("click", selectionDelete);
  $("#sb-forward")?.addEventListener("click", openForwardPicker);
  // Forward modal close + filter.
  $("#forward-cancel")?.addEventListener("click", closeForwardPicker);
  $("#forward-backdrop")?.addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeForwardPicker();
  });
  $("#forward-search")?.addEventListener("input", (e) => {
    renderForwardTargets(e.target.value);
  });
  // Esc to exit selection.
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && state.selecting
        && !$("#forward-backdrop").classList.contains("show")) {
      exitSelection();
    }
  });

  // v0.10.5 bonus polish - slash commands. Preprocesses the
  // composer body before send. Recognized: /shrug, /tableflip,
  // /unflip, /me <text>, /clear (clears pinned), /help.
