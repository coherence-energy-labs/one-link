  function activityIcon(kind, subkind) {
    if (kind === "trust") {
      if (subkind === "verify_set") return "✓";
      if (subkind === "verify_clear") return "↺";
      if (subkind === "trust_set") return "🔒";
      return "⚙";
    }
    if (kind === "key_change") return "⚠";
    if (kind === "transfer") return subkind === "complete" ? "📨" : "✗";
    if (kind === "conflict") return "⚖";
    if (kind === "peer") return "👋";
    if (kind === "folder") {
      if (subkind === "send_failed") return "✗";
      if (subkind === "send_cancelled") return "■";
      if (subkind === "send_retry") return "↻";
      if (subkind === "mode_selected") return "⚙";
      return "📁";
    }
    if (kind === "offer") {
      if (subkind === "offer_declined") return "⊘";
      if (subkind === "offer_accepted") return "✓";
      return "📨";
    }
    return "•";
  }

  async function refreshActivityFeed() {
    const list = $("#activity-list");
    if (!list) return;
    let kindsParam = "";
    if (state.activityFilter && state.activityFilter !== "all") {
      kindsParam = `&kinds=${encodeURIComponent(state.activityFilter)}`;
    }
    let peerParam = "";
    if (state.activityPeerFilter) {
      peerParam = `&peer=${encodeURIComponent(state.activityPeerFilter)}`;
    }
    try {
      const r = await api.get(`/api/activity?limit=500${kindsParam}${peerParam}`);
      state.activityEvents = r.events || [];
    } catch (e) {
      list.innerHTML = "";
      list.appendChild(el("div", "empty", `Couldn\'t load: ${e.message || e}`));
      return;
    }
    renderActivityFeed();
  }

  // Day-bucket label for a timestamp. Today / Yesterday / weekday
  // for the rest of the past week / full date for older. Compared at
  // local-midnight boundaries so a 11:59 PM event doesn't drift into
  // tomorrow's bucket on the page load that crosses midnight.
  function _activityDayBucket(tsMs) {
    const now = new Date();
    const todayStart = new Date(
      now.getFullYear(), now.getMonth(), now.getDate(),
    ).getTime();
    const ts = new Date(tsMs);
    const tsDayStart = new Date(
      ts.getFullYear(), ts.getMonth(), ts.getDate(),
    ).getTime();
    const daysAgo = Math.round((todayStart - tsDayStart) / 86400000);
    if (daysAgo <= 0) return "Today";
    if (daysAgo === 1) return "Yesterday";
    if (daysAgo < 7) {
      return ts.toLocaleDateString(undefined, { weekday: "long" });
    }
    return ts.toLocaleDateString(undefined, {
      month: "short", day: "numeric",
      year: ts.getFullYear() === now.getFullYear() ? undefined : "numeric",
    });
  }

  // Group per-file transfer rows under their parent folder summary
  // (link via folder_send_group). Returns:
  //   { topLevel: events to render, childrenByGroup: {fsg: [...]} }
  // The summary itself stays in topLevel; the children get hidden by
  // default and revealed by the row's expand toggle.
  function _foldActivityRows(events) {
    const childrenByGroup = {};
    const seenSummaryGroups = new Set();
    // First pass: collect all summary-row groups (folder kind with
    // folder_send_group set).
    for (const ev of events) {
      if (
        (ev.kind === "folder" || ev.kind === "offer")
        && ev.folder_send_group
        && (ev.subkind === "send_complete" || ev.subkind === "send_failed"
            || ev.subkind === "send_cancelled")
      ) {
        seenSummaryGroups.add(ev.folder_send_group);
      }
    }
    const topLevel = [];
    for (const ev of events) {
      const fsg = ev.folder_send_group;
      if (
        ev.kind === "transfer"
        && fsg
        && seenSummaryGroups.has(fsg)
      ) {
        // This transfer row belongs to a folder send we have a
        // summary for. Stash it as a child; don't show at top level.
        (childrenByGroup[fsg] = childrenByGroup[fsg] || []).push(ev);
      } else {
        topLevel.push(ev);
      }
    }
    return { topLevel, childrenByGroup };
  }

  function _activityMatchesSearch(ev, needle) {
    if (!needle) return true;
    const n = needle.toLowerCase();
    const haystacks = [
      ev.label, ev.detail, ev.peer_display_name, ev.peer_fp,
      ev.folder_name, ev.subkind, ev.kind, ev.mode,
    ];
    for (const h of haystacks) {
      if (h && String(h).toLowerCase().includes(n)) return true;
    }
    return false;
  }

  function _activityMatchesFailedOnly(ev) {
    if (!state.activityFailedOnly) return true;
    return ev.severity === "bad" || ev.severity === "warn";
  }

  function _setActivityChipActive(filter) {
    document.querySelectorAll('[data-activity-filter]').forEach(
      (b) => b.classList.toggle(
        "active", b.dataset.activityFilter === filter,
      ),
    );
  }

  function renderActivityFeed() {
    const list = $("#activity-list");
    if (!list) return;
    list.innerHTML = "";
    const events = (state.activityEvents || []).filter((ev) => {
      return _activityMatchesSearch(ev, state.activitySearch)
        && _activityMatchesFailedOnly(ev);
    });
    // Render an active-peer-filter banner so the user knows they're
    // looking at a slice + can clear with one click.
    if (state.activityPeerFilter) {
      const banner = el("div", "activity-day-header");
      banner.style.cursor = "pointer";
      banner.title = "Click to clear the per-peer filter";
      banner.textContent = (
        `Filtering by peer · ${state.activityPeerFilter.slice(0, 12)} · `
        + "click to clear"
      );
      banner.onclick = () => {
        state.activityPeerFilter = null;
        refreshActivityFeed();
      };
      list.appendChild(banner);
    }
    if (events.length === 0) {
      list.appendChild(richEmpty(
        "⏱",
        state.activitySearch || state.activityFailedOnly
          || state.activityPeerFilter
          ? "Nothing matches"
          : "No events yet",
        state.activitySearch || state.activityFailedOnly
          || state.activityPeerFilter
          ? "Try clearing the filters or search box above."
          : "Folder sends, pairings, file transfers, and trust events "
            + "show up here as they happen.",
      ));
      return;
    }
    const { topLevel, childrenByGroup } = _foldActivityRows(events);
    let lastBucket = null;
    for (const ev of topLevel) {
      const bucket = _activityDayBucket(ev.ts_ms);
      if (bucket !== lastBucket) {
        list.appendChild(el("div", "activity-day-header", bucket));
        lastBucket = bucket;
      }
      const row = el("div", `activity-row sev-${ev.severity || "info"}`);
      row.appendChild(el("div", "av-icon", activityIcon(ev.kind, ev.subkind)));
      const body = el("div", "av-body");
      const line = el("div", "av-line");
      line.appendChild(el("span", "av-label", ev.label || ev.kind));
      line.appendChild(el("span", "av-time", _humanRelMs(ev.ts_ms)));
      // Folder summary row → expand toggle for the per-file children.
      const kids = ev.folder_send_group
        ? (childrenByGroup[ev.folder_send_group] || []) : [];
      if (kids.length > 0) {
        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.className = "av-folder-toggle";
        const expanded = !!state.activityExpandedGroups[ev.folder_send_group];
        toggle.textContent = `${expanded ? "▾" : "▸"} ${kids.length} files`;
        toggle.title = "Expand to see the individual files in this folder send";
        toggle.onclick = () => {
          state.activityExpandedGroups[ev.folder_send_group] = !expanded;
          renderActivityFeed();
        };
        line.appendChild(toggle);
      }
      body.appendChild(line);
      if (ev.detail) {
        body.appendChild(el("div", "av-detail", ev.detail));
      }
      if (ev.peer_display_name) {
        const peer = el("div", "av-peer", "↳ " + ev.peer_display_name);
        if (ev.peer_fp) {
          peer.classList.add("clickable");
          peer.title = (
            "Filter the feed to events involving this peer only"
          );
          peer.onclick = (e) => {
            e.stopPropagation();
            state.activityPeerFilter = ev.peer_fp;
            refreshActivityFeed();
          };
        }
        body.appendChild(peer);
      }
      // Expanded children list (folder send's per-file rows).
      if (kids.length > 0
          && state.activityExpandedGroups[ev.folder_send_group]) {
        const cwrap = el("div", "av-children");
        const SHOW = 100;
        const shown = kids.slice(0, SHOW);
        const overflow = kids.length - shown.length;
        for (const child of shown) {
          const crow = el(
            "div",
            "av-children-row" + (
              child.severity === "bad" ? " failed" : ""
            ),
          );
          const nameSpan = el("span", "child-name", child.label || "?");
          nameSpan.title = child.label || "";
          const detailSpan = el(
            "span", "child-detail", child.detail || "",
          );
          crow.appendChild(nameSpan);
          crow.appendChild(detailSpan);
          cwrap.appendChild(crow);
        }
        if (overflow > 0) {
          cwrap.appendChild(el(
            "div", "av-children-overflow",
            `…and ${overflow} more`,
          ));
        }
        body.appendChild(cwrap);
      }
      row.title = new Date(ev.ts_ms).toLocaleString();
      row.appendChild(body);
      list.appendChild(row);
    }
  }

  // Wire filter chips. The "Issues only" severity chip is special —
  // toggles a separate flag instead of replacing the kind filter, so
  // a user can say "show me only failed Folders" by combining both.
  document.querySelectorAll('[data-activity-filter]').forEach((btn) => {
    btn.addEventListener("click", () => {
      const filter = btn.dataset.activityFilter;
      state.activityFilter = filter;
      _setActivityChipActive(filter);
      refreshActivityFeed();
    });
  });
  const failedOnlyChip = document.getElementById("activity-failed-only-chip");
  if (failedOnlyChip) {
    failedOnlyChip.addEventListener("click", () => {
      state.activityFailedOnly = !state.activityFailedOnly;
      failedOnlyChip.classList.toggle("active", state.activityFailedOnly);
      renderActivityFeed();  // local-only, no refetch needed
    });
  }
  // Search box — debounced re-render so typing doesn't thrash.
  const activitySearchInput = document.getElementById("activity-search-input");
  if (activitySearchInput) {
    let searchTimer = null;
    activitySearchInput.addEventListener("input", () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        state.activitySearch = activitySearchInput.value.trim();
        renderActivityFeed();
      }, 120);
    });
  }

  // v0.10.6: clickable Activity tiles. Each of the four mesh
  // counters drills into the most useful surface for that number:
  //   nearby      -> Activity nearby device panel
  //   moving now  -> Files Sent tab
  //   saved chunks-> Activity filter "transfer"
  //   secure links-> Activity filter "trust"
  function _activateActivityFilter(name) {
    const chip = document.querySelector(`[data-activity-filter="${name}"]`);
    if (chip) chip.click();
  }
  async function _openActivityNearbyFromTile() {
    const meshBtn = document.querySelector('[data-pane="mesh"]');
    if (meshBtn && !_phoneCannotShow(meshBtn) && state.activePane !== "mesh") {
      meshBtn.click();
    }
    await loadActivityNearby({ force: true });
    const count = nearbyCount();
    toast(
      count ? `Found ${count} nearby device${count === 1 ? "" : "s"}.` : "Scanning nearby devices...",
      "info",
      3000,
    );
  }
  function _handleMeshTile(kind) {
    if (kind === "online") {
      _openActivityNearbyFromTile().catch((e) => {
        toast(`Nearby scan failed: ${errorToastBody(e)}`, "bad", 5000);
      });
    } else if (kind === "active") {
      const filesBtn = document.querySelector('[data-pane="files"]');
      const sentBtn = document.querySelector('[data-files-mode="sent"]');
      // Phone has no Files pane; skip if the target is hidden.
      if (_phoneCannotShow(filesBtn)) return;
      filesBtn.click();
      state.filesMode = "sent";
      if (sentBtn) sentBtn.click();
    } else if (kind === "cache") {
      _activateActivityFilter("transfer");
    } else if (kind === "sessions") {
      _activateActivityFilter("trust");
    }
  }
  document.querySelectorAll('[data-mesh-tile]').forEach((tile) => {
    tile.addEventListener("click", () => _handleMeshTile(tile.dataset.meshTile));
    tile.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        _handleMeshTile(tile.dataset.meshTile);
      }
    });
  });

  // Schedule a refresh - coalesce many WS events per frame.
  $("#one-now-send")?.addEventListener("click", () => {
    const filesBtn = document.querySelector('[data-pane="files"]');
    if (filesBtn && !_phoneCannotShow(filesBtn)) {
      filesBtn.click();
      $("#btn-send-file-panel")?.click();
      return;
    }
    $("#btn-attach")?.click();
  });
  $("#one-now-devices")?.addEventListener("click", () => {
    const meshBtn = document.querySelector('[data-pane="mesh"]');
    if (meshBtn) meshBtn.click();
    chooseBestSelfMeshDevice();
    $("#self-mesh-kit")?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  });
  $("#one-now-privacy")?.addEventListener("click", () => {
    $("#btn-privacy")?.click();
  });
  $("#activity-nearby-close")?.addEventListener("click", (ev) => {
    ev.stopPropagation();
    closeActivityNearby();
  });

  let _activityRefreshScheduled = false;
  function scheduleActivityRefresh() {
    if (_activityRefreshScheduled) return;
    _activityRefreshScheduled = true;
    requestAnimationFrame(() => {
      _activityRefreshScheduled = false;
      // Only refresh if pane is open OR we're idle. Saves a fetch
      // per WS event when the user isn't looking.
      if (state.activePane === "mesh") refreshActivityFeed();
    });
  }

