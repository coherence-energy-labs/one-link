  // ── peers card hydration ───────────────────────────────────────────
  async function _refreshPeersCard() {
    show($("#peers-card"));
    const list = $("#peers-list");
    const empty = $("#peers-empty");
    if (!list || !empty) return;
    text(empty, "No paired peers yet. Pair a connection above to add the first one.");
    let peers = [];
    try {
      peers = await listPeers();
    } catch (error) {
      list.innerHTML = "";
      list.style.display = "none";
      text(
        empty,
        "The peer roster could not be verified. One Link did not hide, " +
        "replace, or delete any record. Restore a known-good browser backup " +
        `before pairing again (${error && error.message ? error.message : error}).`,
      );
      show(empty);
      return;
    }
    if (!peers.length) {
      list.style.display = "none";
      show(empty);
      return;
    }
    hide(empty);
    list.style.display = "flex";
    list.innerHTML = "";
    for (const peer of peers) {
      const row = document.createElement("div");
      row.style.display = "flex";
      row.style.gap = "10px";
      row.style.alignItems = "center";
      row.style.padding = "10px 12px";
      row.style.background = "var(--bg-3)";
      row.style.borderRadius = "10px";

      const left = document.createElement("div");
      left.style.flex = "1 1 auto";
      left.style.minWidth = "0";
      const name = document.createElement("div");
      name.textContent = peer.alias || (peer.fingerprint.split(":").pop() || "").slice(0, 12);
      name.style.fontWeight = "600";
      name.style.fontSize = "14px";
      const fp = document.createElement("div");
      fp.textContent = peer.fingerprint;
      fp.style.fontFamily = "ui-monospace, SFMono-Regular, Consolas, monospace";
      fp.style.fontSize = "11px";
      fp.style.color = "var(--text-dim)";
      fp.style.overflow = "hidden";
      fp.style.textOverflow = "ellipsis";
      fp.style.whiteSpace = "nowrap";
      const ts = document.createElement("div");
      ts.textContent = `Paired ${new Date(peer.paired_ms).toLocaleString()}`;
      ts.style.fontSize = "11px";
      ts.style.color = "var(--text-dimmer)";
      left.appendChild(name);
      left.appendChild(fp);
      left.appendChild(ts);

      const forget = document.createElement("button");
      forget.textContent = "Forget";
      forget.className = "btn ghost";
      forget.style.padding = "6px 12px";
      forget.style.minHeight = "auto";
      forget.style.fontSize = "12px";
      forget.onclick = async () => {
        if (!confirm(`Forget ${peer.fingerprint}? You'll need to re-pair to reach this device.`)) return;
        await deletePeer(peer.fingerprint);
        await _refreshPeersCard();
      };

      row.appendChild(left);
      row.appendChild(forget);
      list.appendChild(row);
    }
  }

