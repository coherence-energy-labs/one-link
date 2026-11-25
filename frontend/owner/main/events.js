  // ── WebSocket live events ──────────────────────────────────────────
  let ws = null;
  // Call events the call driver threw on (reported in diagnostics).
  let _callEventHandlerFailures = 0;
  function callEventHandlerFailures() {
    return _callEventHandlerFailures;
  }
  function connectWS() {
    try { if (ws) ws.close(); } catch {}
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const bearer = _ownerBearerToken();
    const protocols = ["one-link.owner.v1"];
    if (bearer) protocols.push(`one-link.bearer.${bearer}`);
    ws = new WebSocket(`${proto}//${location.host}/api/events`, protocols);
    ws.onopen = LiveRefresh.onOpen;
    ws.onmessage = (ev) => {
      let m;
      try { m = JSON.parse(ev.data); } catch { return; }
      if (m.type === "peers" || m.type === "peers_changed") {
        // v0.4: daemon now signals "peers_changed"; legacy "peers" event
        // tolerated for forward/backward compat.
        refreshPeers();
        if (state.discoverOpen) loadDiscoverable();
      } else if (m.type === "call_event") {
        // Living Presence Tier α-pre - call lifecycle / consent
        // / capsule events broadcast by the daemon's CallManager.
        // Forward to the call-UI driver defined later in this page.
        try {
          if (typeof window.handleLivingPresenceCallEvent === "function") {
            window.handleLivingPresenceCallEvent(m);
          }
        } catch (error) {
          // Never let the call UI crash the event stream, and never hide
          // its failure either: count it for diagnostics and log it.
          _callEventHandlerFailures += 1;
          console.error(
            `call event handler failed (${_callEventHandlerFailures} so far):`,
            m && m.tail_kind, error,
          );
        }
      } else if (m.type === "frame_provenance") {
        // Living Presence Tier α-pre - daemon verified an inbound
        // FILE_PROVENANCE message (or recorded our own outbound
        // provenance). Update the local map so subsequent
        // renderFileBubble calls render the Reality dot.
        // Payload shape (from provenance_wiring.ProvenanceStore.ui_state_for_blob):
        //   { blob, kind, path, recording, verified, produced_at_us }
        if (m.blob && typeof m.blob === "string") {
          state.provenanceByBlob.set(m.blob, {
            kind: m.kind,
            path: m.path,
            recording: m.recording,
            verified: !!m.verified,
            produced_at_us: m.produced_at_us,
          });
          // Re-render visible messages so the dot appears on any
          // already-rendered bubble matching this blob.
          if (typeof renderMessages === "function") {
            try { renderMessages(); } catch (_) { /* defensive */ }
          }
        }
      } else if (m.type === "peer_trust") {
        scheduleActivityRefresh();  // v0.9.1: surface in activity feed
        // v0.10.3: first-pair nudge. Track on a per-fingerprint
        // basis so subsequent pairings (with the same OR different
        // peers) don't re-pop the nudge.
        if (m.trust === "pinned") {
          maybeShowFirstPairNudge(m.fingerprint);
        }
        if (state.pairing.peerFp === m.fingerprint && m.trust === "pinned") {
          // v0.8.7: local confirm pivots with enterPairVerifyStage().
          toast("Paired", "good");
          if (state.pairing.weConfirmed) {
            enterPairVerifyStage();
          } else {
            // Other device confirmed first; stay on stage 1 so the
            // local user still has a chance to mismatch-cancel.
            // pairMatch will pivot when they click.
            pairExplain.textContent = "The other device confirmed. Click 'They match' to finish.";
          }
        }
        refreshPeers();
      } else if (m.type === "peer_profile" || m.type === "peer_capabilities") {
        // v0.7.3: alias / mute / cap changes - refresh the sidebar so
        // the new display name and toggle states show up immediately.
        refreshPeers();
      } else if (m.type === "folder_conflict_detected") {
        scheduleActivityRefresh();  // v0.9.1: surface in activity feed
        // v0.8.9: live conflict - refresh the banner + (if open)
        // the modal so the new entry appears immediately.
        toast(
          `Folder conflict in "${m.conflict?.folder_name || "?"}": ${m.conflict?.file_path || ""}`,
          "warn", 7000,
        );
        refreshFolderConflictsBanner();
        if ($("#conflicts-backdrop").classList.contains("show")) {
          renderConflictsModal();
        }
      } else if (m.type === "folder_conflict_resolved") {
        // Another tab resolved one - clear it from our view.
        refreshFolderConflictsBanner();
        if ($("#conflicts-backdrop").classList.contains("show")) {
          renderConflictsModal();
        }
      } else if (m.type === "folder_offer_received") {
        // v0.21.x: a paired peer wants to share a folder we
        // don't have. Refresh the offers section + flash a toast
        // so the user notices even if they're not on the Folders
        // tab right now.
        refreshFolderOffers();
        const o = m.offer || {};
        toast(
          `New folder share offer: "${o.folder_name || "?"}". Open Folders to Accept or Decline.`,
          "info", 6000,
        );
      } else if (m.type === "folder_offer_declined") {
        refreshFolderOffers();
      } else if (m.type === "folder_offer_pull_complete") {
        // Accept-pull finished: the blobs arrived. Refresh the
        // folders list so the new folder + its file count show.
        const fname = m.folder_name || "?";
        const blobs = m?.result?.blobs_sent;
        if (typeof blobs === "number" && blobs > 0) {
          toast(`"${fname}" is ready (${blobs} file${blobs === 1 ? "" : "s"} synced).`, "good", 5000);
        }
        refreshFolders();
      } else if (m.type === "folder_offer_pull_failed") {
        toast(
          `Couldn't sync "${m.folder_name || "?"}" yet: ${m.error || "the other device may be offline."}`,
          "warn", 7000,
        );
      } else if (m.type === "folder_share_pushed") {
        // Sender-side: confirmation that our auto-push-after-Share
        // landed at the peer (may still be in_pending state if peer
        // hasn't accepted yet). Quiet refresh.
        refreshFolders();
      } else if (m.type === "folder_scan_complete") {
        refreshFolders();
      } else if (m.type === "folder_send_complete") {
        // v0.21.x one-shot folder send finished.
        const failed = m.failed || 0;
        const mode = m.mode || "per_file";
        let body;
        if (mode === "manifest_push") {
          if (failed > 0 || !m.ok) {
            body = `Folder send failed: ${m.name || ""} — ${m.error || "unknown error"}`;
          } else {
            body = `Folder ${m.name || ""} delivered`;
            if (m.sent > 0) body += ` · ${m.sent} new blob${m.sent === 1 ? "" : "s"} streamed`;
            else body += ` · already on the other device (dedup)`;
          }
          toast(body, (failed > 0 || !m.ok) ? "bad" : "good", 7000);
          hideFolderSendProgress();
          return;
        }
        if (mode === "archive") {
          // ARCHIVE mode — one transfer for the whole folder.
          if (failed > 0) {
            body = `Folder send failed: ${m.name || ""} — ${m.error || "unknown error"}`;
          } else {
            const orig = m.original_size || 0;
            const arch = m.archive_size || 0;
            const ratio = m.compression_ratio || 0;
            const savedPct = Math.round(ratio * 100);
            body = `Folder ${m.name || ""} sent as one archive`;
            if (orig > 0 && arch > 0) {
              body += ` · ${_humanBytes(orig)} → ${_humanBytes(arch)}`;
              if (savedPct > 0) body += ` (${savedPct}% smaller)`;
            }
          }
          toast(body, failed > 0 ? "bad" : "good", 7000);
        } else {
          const sent = m.sent || 0;
          const dedup = m.dedup_files || 0;
          const dedupBytes = m.dedup_bytes || 0;
          body = `Sent ${_fmtFiles(sent)}`;
          if (dedup > 0) {
            body += ` · ${_fmtFiles(dedup)} already on device (${_humanBytes(dedupBytes)} skipped)`;
          }
          if (failed > 0) {
            body += ` · ${failed} failed`;
          }
          toast(body, failed > 0 ? "bad" : "good", 7000);
        }
        hideFolderSendProgress();
      } else if (m.type === "folder_send_cancelled") {
        toast(`Send cancelled — sent ${m.sent || 0}, ${m.remaining || 0} not sent.`, "info", 5000);
        hideFolderSendProgress();
      } else if (m.type === "folder_recv_blob_done") {
        // v0.21.x Wave 6: per-blob progress as we receive a folder.
        // Aggregate live so the Folders pane shows a progress count
        // without polling. Stash in state.folderRecvProgress; the
        // folder card renderer reads from it.
        state.folderRecvProgress = state.folderRecvProgress || {};
        const peerKey = String(m.peer_fp || "anon").slice(0, 16);
        const cur = state.folderRecvProgress[peerKey] || {
          blobsDone: 0, bytesDone: 0, lastSeen: 0,
        };
        cur.blobsDone += 1;
        cur.bytesDone += Number(m.size || 0);
        cur.remaining = Number(m.remaining || 0);
        cur.lastSeen = Date.now();
        state.folderRecvProgress[peerKey] = cur;
        // v0.21.x: rAF-debounced re-render so the folder card's
        // "Receiving N blobs" line updates live without firing N
        // refreshFolders for an N-blob transfer.
        if (!state._folderRecvRenderScheduled) {
          state._folderRecvRenderScheduled = true;
          requestAnimationFrame(() => {
            state._folderRecvRenderScheduled = false;
            if (typeof refreshFolders === "function") {
              refreshFolders();
            }
          });
        }
      } else if (m.type === "folder_send_blob_done") {
        // v0.21.x: per-blob send progress (sender side). Update the
        // in-flight overlay's detail line so the user sees real
        // progress instead of static "Sending paper". Stash by peer_fp
        // so multi-peer fan-out updates each card independently.
        state.folderSendProgress = state.folderSendProgress || {};
        const key = `${m.folder_name}::${m.peer_fp}`;
        state.folderSendProgress[key] = {
          folder_name: m.folder_name, peer_fp: m.peer_fp,
          blobs_done: m.blobs_done || 0,
          blobs_total: m.blobs_total || 0,
          bytes_done: m.bytes_done || 0,
          bytes_total: m.bytes_total || 0,
          last_seen: Date.now(),
        };
        // Update the in-flight overlay if we're sending to this peer.
        const cur = state.folderSendInflight;
        if (cur && cur.peerFp === m.peer_fp && cur.displayName === m.folder_name) {
          const detail = $("#fsp-detail");
          if (detail) {
            const total = m.blobs_total || 0;
            const done = m.blobs_done || 0;
            const pct = total > 0 ? Math.round((done / total) * 100) : 0;
            detail.textContent = (
              `${done} of ${total} blob${total === 1 ? "" : "s"} · `
              + `${_humanBytes(m.bytes_done || 0)} sent · ${pct}%`
            );
          }
        }
      } else if (m.type === "folder_recv_collision") {
        // v0.21.x: incoming folder write overwrote a local file with
        // different content. CRDT decided who wins; the user just
        // needs to know it happened so they can recover from chunk
        // cache if their version was the one that lost. Toast is
        // info-level (the system did the right thing per the
        // folder's conflict_policy).
        const path = m.file_path || "a file";
        const folder = m.folder_name || "folder";
        toast(
          `Overwrote ${path} in ${folder} `
            + `(${_humanBytes(m.existing_size || 0)} → `
            + `${_humanBytes(m.incoming_size || 0)})`,
          "info", 7000,
        );
      } else if (m.type === "folder_send_retrying") {
        // v0.21.x: folder send dropped mid-flight on a transient
        // error (link drop, timeout). We're retrying. Receiver's
        // chunk cache means resume is free; just need to wait the
        // backoff + reconnect. Surface as a soft info toast.
        toast(
          `Retrying ${m.name || "folder"} (attempt ${m.attempt}/${m.max_attempts}, `
            + `${m.backoff_seconds}s)`,
          "info", 3500,
        );
      } else if (m.type === "folder_send_declined_by_peer") {
        // v0.21.x: receiver explicitly declined our folder send.
        // The daemon already cancelled any in-flight task + revoked
        // the temp share grant; UI just shows the user what happened
        // and tears down the inflight progress overlay.
        toast(
          `${m.folder_name || "Folder"} declined by the other device.`
            + (m.cancelled_in_flight
                ? " In-flight transfer cancelled."
                : ""),
          "info", 7000,
        );
        if (typeof hideFolderSendProgress === "function") {
          hideFolderSendProgress();
        }
        if (typeof refreshFolders === "function") refreshFolders();
      } else if (m.type === "folder_self_mesh_auto_accepted") {
        // v0.21.x: own paired device sent us a folder. Auto-accepted
        // (implicit consent for self-mesh) — show ONE notification
        // instead of an Accept/Decline card. Also refresh the
        // folder-offers list so any stale "pending" card from before
        // the auto-accept marked it accepted gets cleared.
        toast(
          `Folder ${m.folder_name || ""} arriving from your other device`,
          "good", 6000,
        );
        if (typeof refreshFolders === "function") refreshFolders();
        if (typeof refreshFolderOffers === "function") refreshFolderOffers();
      } else if (m.type === "folder_archive_received") {
        // v0.21.x: receiver-side notification when a folder archive
        // arrives + extracts. ONE toast for the whole folder; users
        // see "Folder received" not 147 individual file toasts.
        const n = m.files_extracted || 0;
        const bytes = m.bytes_extracted || 0;
        const folder = m.folder_name || "folder";
        toast(
          `Folder received: ${folder} (${_fmtFiles(n)} · ${_humanBytes(bytes)})`,
          "good", 8000,
        );
        // Also refresh the files pane in case the user is looking at it.
        if (typeof refreshTransfers === "function") refreshTransfers();
      } else if (m.type === "key_change_acked" || m.type === "key_change_acked_all") {
        // v0.7.8: another tab acknowledged. Refresh peers so the
        // banner / overlay clears for everyone live.
        refreshPeers();
      } else if (
        m.type === "peer_rotated" ||
        m.type === "rotation_announcement_acked"
      ) {
        // v0.21.x identity rotation: a peer either rotated their
        // key (inbound cert applied + atomic peer-fingerprint
        // transition) OR acknowledged a rotation we're propagating
        // to them. In both cases refresh peers so the sidebar
        // shows the new identity, and re-render the rotation card
        // in the recovery wizard if it's open so the per-peer
        // ack list updates live without the user clicking Refresh.
        refreshPeers();
        const wiz = document.getElementById("recovery-wizard");
        if (wiz && wiz.classList.contains("show")) {
          try { _recwizRenderRotateCard(); } catch (_) { /* defensive */ }
        }
        // Refresh the home-screen rotation banner so it auto-hides
        // when the last peer acks (or updates the X of Y count
        // when only some peers acked).
        try { refreshRotationBanner(); } catch (_) { /* defensive */ }
        if (m.type === "peer_rotated") {
          scheduleActivityRefresh();  // peer-rotation events show up in activity
          // Surface a calm informational toast so the user sees
          // their friend rotated even when they're looking at a
          // different conversation. Resolve a display label from
          // the existing peers map (alias > hostname > short_id)
          // so the toast says 'Alice rotated their identity key'
          // not 'a1b2c3 rotated their identity key'.
          try {
            const newFp = m.new_fingerprint || "";
            // state.peers is a Map keyed by fingerprint. Try the
            // NEW fingerprint first (post-transition) then fall
            // back to the OLD one if the WS event raced ahead of
            // the peers refresh.
            const peer = (newFp && state.peers && state.peers.get
              ? state.peers.get(newFp) : null)
              || (m.old_fingerprint && state.peers && state.peers.get
                ? state.peers.get(m.old_fingerprint) : null);
            const label = (peer && (
              peer.local_alias || peer.alias || peer.display_name ||
              peer.hostname || peer.short_id
            )) || (newFp ? `${newFp.slice(0, 8)}…` : "A trusted peer");
            toast(
              `${label} rotated their identity key. Your trust transferred automatically.`,
              "info", 6000,
            );
          } catch (_) { /* defensive - never let UI handler crash WS */ }
        }
      } else if (m.type === "key_change_detected") {
        scheduleActivityRefresh();  // v0.9.1: surface in activity feed
        // v0.7.8: a hostname↔pubkey rotation just got logged. Pop
        // a loud toast so the user notices even with the chat
        // surface scrolled to a different conversation, then trigger
        // peers_changed via refreshPeers so every UI surface
        // (sidebar overlay, conv banner, drawer) updates atomically.
        const ev = m.event || {};
        const sevTag = (ev.severity || "low").toUpperCase();
        toast(
          `[${sevTag}] Key change detected for "${ev.hostname || "?"}".`,
          "bad", 8000,
        );
        refreshPeers();
      } else if (m.type === "self_presence") {
        // v0.10.4: another tab changed our presence - sync.
        applyPresenceUI(m.presence);
      } else if (m.type === "chat_pref") {
        // v0.12.1: another tab (or another device) changed a per-
        // chat preference. Mirror into local cache + re-render
        // anything that consumes that pref.
        const { scope, id, kind, value } = m;
        if (state.chatPrefs && scope && id && kind) {
          settingsStore.setChatPref(scope, id, kind, value);
          if (scope === "group") renderGroups();
          if (scope === "peer") renderPeers();
          applyActiveChatWallpaper();
        }
      } else if (m.type === "peer_presence") {
        // v0.10.4: a peer reported a status change. Patch the
        // cached record + re-render the sidebar so the avatar
        // dot tints update.
        const peer = [...state.peers.values()]
          .find(p => p.fingerprint === m.fingerprint);
        if (peer) {
          peer.presence = m.presence;
          renderPeers();
        }
      } else if (m.type === "self_mesh_changed") {
        refreshSelfMesh();
        refreshOneHealth();
        scheduleActivityRefresh();
      } else if (m.type === "peer_verified") {
        scheduleActivityRefresh();  // v0.9.1: surface in activity feed
        // v0.7.7: side-channel SAS confirm flipped on/off. Patch the
        // peer record in-place so the avatar overlay + conversation
        // header pill update without waiting for the next /api/peers
        // poll.
        const peer = [...state.peers.values()]
          .find(p => p.fingerprint === m.fingerprint);
        if (peer) {
          peer.verified_at_ms = m.verified_at_ms;
          peer.verified_method = m.verified_method;
          peer.verified_note = m.verified_note;
          peer.is_verified = !!m.is_verified;
          renderPeers();
          if (state.selectedPeer === peer.short_id) {
            renderConvHeaderTrust(peer);
          }
          if (state.deviceDrawerFp === m.fingerprint) {
            renderDrawerVerification(peer);
          }
        }
        // Best-effort full refresh in case the peer wasn't yet in
        // our cache.
        refreshPeers();
      } else if (m.type === "msg_edit") {
        // v0.7.6: live edit. Patch the in-memory message + rerender.
        if (messageStore.editMessage("direct", m.target, m.body, m.edited_at_ms)) {
          scheduleRenderMessages();
        }
      } else if (m.type === "msg_delete") {
        if (messageStore.tombstoneMessage("direct", m.target, m.deleted_at_ms)) {
          scheduleRenderMessages();
        }
      } else if (m.type === "update_status") {
        // v0.21.x: daemon's background poll says the GitHub-Releases
        // picture changed. Re-fetch /api/update/check so the banner
        // appears/clears without a page reload. ?fresh=1 bypasses the
        // server-side 15-min cache (we want the change reflected now).
        // checkForUpdate() reads from the cached endpoint by default,
        // so we hit /api/update/check?fresh=1 to push past the cache.
        (async () => {
          try { await api.get("/api/update/check?fresh=1"); } catch (_e) {}
          try { await checkForUpdate(); } catch (_e) {}
        })();
      } else if (m.type === "peer_typing") {
        // v0.12.3: a peer reports they're typing. Cache the
        // expires_at_ms so we can render the banner + auto-hide
        // when the deadline passes. Honors display privacy: if
        // off, the daemon broadcasts to other tabs but we treat
        // each tab independently - a tab where the user has the
        // toggle off should still drop the banner. (The daemon
        // does the gating; this is belt-and-suspenders.)
        if (state.runtimeSettings?.display_typing_indicators === false) return;
        if (!/^[0-9a-f]{64}$/i.test(String(m.peer_fp || ""))) return;
        const deadline = Number(m.expires_at_ms);
        if (!Number.isSafeInteger(deadline)
            || deadline <= Date.now() || deadline > Date.now() + 15000) return;
        state.peerTyping = state.peerTyping || {};
        state.peerTyping[m.peer_fp] = deadline;
        renderTypingBanner();
      } else if (m.type === "group_typing") {
        // Pairwise-authenticated group typing is keyed by both group and
        // sender so concurrent composers render accurately and removed
        // members can be expired independently.
        if (state.runtimeSettings?.display_typing_indicators === false) return;
        const gid = m.group_id_hex || m.group_id;
        if (!/^[0-9a-f]{32}$/i.test(String(gid || ""))) return;
        if (!/^[0-9a-f]{64}$/i.test(String(m.peer_fp || ""))) return;
        const deadline = Number(m.expires_at_ms);
        if (!Number.isSafeInteger(deadline)
            || deadline <= Date.now() || deadline > Date.now() + 15000) return;
        state.groupTyping = state.groupTyping || {};
        state.groupTyping[gid] = state.groupTyping[gid] || {};
        state.groupTyping[gid][m.peer_fp] = deadline;
        renderTypingBanner();
      } else if (m.type === "read_marker") {
        // v0.7.6: peer reported they've read up to ts X. Update
        // our local map; render flips outbound ✓ → ✓✓ for all
        // messages with ts ≤ X.
        // v0.12.2: also record received_at so the ✓✓ tooltip can
        // show "Read at HH:MM" instead of just "Read".
        const cur = state.readMarkers[m.peer_fp] || 0;
        if (m.up_to_ts_ms > cur) {
          state.readMarkers[m.peer_fp] = m.up_to_ts_ms;
          state.readMarkerReceivedAt = state.readMarkerReceivedAt || {};
          state.readMarkerReceivedAt[m.peer_fp] = Date.now();
          scheduleRenderMessages();
        }
      } else if (m.type === "debug_event") {
        // v0.8.1: live debug entry. Prepend if pane is open;
        // otherwise just bump the unread count badge.
        const e = m.entry;
        if (e) {
          // Avoid double-counting on incremental refresh.
          if (e.id > state.debugLastId) {
            state.debugEntries.unshift(e);
            state.debugLastId = e.id;
            const cap = 500;
            if (state.debugEntries.length > cap) {
              state.debugEntries.length = cap;
            }
            if (state.activePane === "debug") renderDebugLog();
            $("#debug-error-count").textContent = state.debugEntries
              .filter(x => x.severity === "error").length;
          }
        }
      } else if (m.type === "courier_files") {
        refreshCourierStatus();
        if (state.activePane === "mesh") {
          toast("Offline delivery folder changed", "info", 2200);
        }
      } else if (m.type === "removable_media") {
        state.courier = state.courier || {};
        state.courier.removable_targets = Array.isArray(m.targets) ? m.targets : state.courier.removable_targets;
        state.courier.removable_events = Array.isArray(m.events) ? m.events : [];
        renderCourierKit();
        refreshCourierStatus();
        if (state.activePane === "mesh") {
          const first = state.courier.removable_events[0] || {};
          const kind = String(first.kind || "changed").replace(/_/g, " ");
          toast(`Removable media ${kind}`, "info", 2600);
        }
      } else if (m.type === "group_msg") {
        const gid = m.group_id_hex || m.group_id;
        if (gid && gid === state.selectedGroup) {
          const row = {
            id: m.id,
            group_id: gid,
            sender_pub_hex: m.sender_pub_hex,
            epoch: m.epoch,
            counter: m.counter,
            direction: m.direction,
            body: m.body,
            reply_to: m.reply_to,
            ts_ms: m.ts_ms || Date.now(),
          };
          messageStore.upsertGroupRow(row);
          renderGroupConversation();
        }
      } else if (m.type === "group_msg_edit") {
        if ((m.group_id_hex || m.group_id) === state.selectedGroup) {
          if (messageStore.editMessage("group", m.target, m.body, m.edited_at_ms)) {
            renderGroupConversation();
          }
        }
      } else if (m.type === "group_msg_delete") {
        if ((m.group_id_hex || m.group_id) === state.selectedGroup) {
          if (messageStore.tombstoneMessage("group", m.target, m.deleted_at_ms)) {
            renderGroupConversation();
          }
        }
      } else if (m.type === "group_reaction") {
        if ((m.group_id_hex || m.group_id) === state.selectedGroup) {
          if (messageStore.applyReaction("group", m.target, m.op, m.emoji, m.peer_fp)) {
            renderGroupConversation();
          }
        }
      } else if (m.type === "group_event" || m.type === "group_created") {
        // v0.8.0: groups changed. Refresh both the sidebar list
        // AND, if we're viewing the affected group, its messages
        // + member list.
        refreshGroups();
        if (state.selectedGroup &&
            (m.group_id === state.selectedGroup ||
             m.type === "group_created")) {
          selectGroup(state.selectedGroup);
        }
      } else if (m.type === "reaction") {
        // v0.7.5: live reaction event. Apply to whichever in-memory
        // message matches the target id, then re-render.
        if (messageStore.applyReaction("direct", m.target, m.op, m.emoji, m.peer_fp)) {
          scheduleRenderMessages();
        }
      } else if (m.type === "pair_request") {
        // Incoming pair request from another device. Open the same modal
        // so the user verifies the SAS. v0.4: requester is by definition
        // unpaired, so it lives in state.discoverable, not state.peers.
        // Fetch fresh to make sure we have current address/port info.
        (async () => {
          try {
            const { peers } = await api.get("/api/peers?include_unpaired=1");
            const peer = peers.find(p => p.fingerprint === m.peer_fp);
            if (peer) {
              openPairModalIncoming(
                peer,
                m.sas,
                m.sas_phrase || m.sas_words || "",
              );
            } else {
              toast("Incoming pair request - refreshing devices…", "info");
            }
          } catch (e) {
            console.warn(e);
          }
        })();
      } else if (m.type === "pair_progress") {
        // Peer confirmed on their side; if we already confirmed, daemon
        // pins. Otherwise the modal stays open waiting for our user.
      } else if (m.type === "pair_rejected") {
        if (state.pairing.peerFp === m.peer_fp) {
          closePairModal(false);
          toast("The other device rejected pairing", "bad");
        }
        if (state.discoverOpen) loadDiscoverable();
      } else if (m.type === "msg") {
        const msg = m.msg;
        // v0.21.x: if an outbound message comes back with an id we
        // already painted as an optimistic bubble (client_msg_id was
        // threaded through the daemon), REPLACE the placeholder
        // record so we end up with one canonical bubble carrying
        // the server's authoritative ts / metadata. Without this
        // we'd render twice on the fast path. Same applies if the
        // user happens to receive an echo for any id we've already
        // got — replace, don't duplicate. Local-only fields
        // (_sendingState etc.) the event lacks are kept, but the row is
        // marked sent now that the daemon confirms it. messageStore
        // keeps the newest 800 once history passes 1000 rows.
        messageStore.receiveDirect(msg);
        if (msg.t === "TEXT" && msg.dir === "in") {
          const peer = state.peers.get(msg.peer);
          const who = peer?.display_name || peer?.hostname || msg.peer;
          if (msg.peer !== state.selectedPeer && !peer?.muted) {
            toast(`${who}: ${msg.body || ""}`, "info");
          }
          // v0.21.x: bump unread when this message isn't visibly being
          // read right now (peer not selected OR window not focused).
          const isReadingThisPeer = msg.peer === state.selectedPeer
            && !document.hidden
            && document.hasFocus();
          if (!isReadingThisPeer && !peer?.muted) bumpUnread(msg.peer);
          notifyIncoming(who, msg.body || "", { peer_fp: peer?.fingerprint });
        }
        if (msg.t === "FILE_OFFER" && msg.dir === "in") {
          // File offers also count as unread until the user opens the chat.
          const peer = state.peers.get(msg.peer);
          const isReadingThisPeer = msg.peer === state.selectedPeer
            && !document.hidden
            && document.hasFocus();
          if (!isReadingThisPeer && !peer?.muted) bumpUnread(msg.peer);
        }
        if (msg.t === "FILE_DONE" && msg.dir === "in" && msg.ok) {
          const peer = state.peers.get(msg.peer);
          const who = peer?.display_name || peer?.hostname || msg.peer;
          if (!peer?.muted) toast(`Received ${msg.name || "file"}`, "good");
          notifyIncoming(`File from ${who}`, msg.name || "file", { peer_fp: peer?.fingerprint });
          refreshFiles();
        }
        if (msg.peer === state.selectedPeer) renderMessages();
      } else if (m.type === "traces_cleared") {
        if (m.scope === "chat" || m.scope === "all") {
          loadHistory();
        }
        if (m.scope === "files" || m.scope === "all") {
          refreshFiles();
          refreshTransfers();
        }
        if (m.scope === "folders" || m.scope === "all") {
          refreshFolders();
        }
        if (m.scope === "activity" || m.scope === "all") {
          refreshActivityFeed();
          refreshTransfers();
        }
        refreshStorageUsage();
      } else if (m.type === "file_offer_pending") {
        // Accept-first: someone is sending a standalone file and it's
        // waiting for our OK. Show the Accept/Decline prompt.
        showFileOfferPrompt(m);
        refreshAttention().catch(()=>{});
      } else if (m.type === "file_offer_resolved") {
        _removeFileOfferPrompt(m.transfer_id);
        refreshAttention().catch(()=>{});
      } else if (m.type === "transfer") {
        // Any transfer state change can flip an item into / out of
        // the attention list (stuck → unstuck, failed → dismissed,
        // held → accepted). Coalesce via the scheduler.
        scheduleAttentionRefresh();
        // transferStore replaces or prepends the row, keeps the list
        // newest-first and capped at 80, and prunes evicted rows from
        // the by-id Map and the (dir|blob) index (2026-05-22 audit
        // Batch AA: the Map used to grow for the whole session). T3-Z:
        // it keeps the index in sync so transferForMessage stays O(1).
        transferStore.applyEvent(m.transfer);
        // v0.8.8: update the per-transfer EWMA bytes-per-second
        // tracker so the chat bubble + header pill can show a live
        // rate. Cleared on terminal status (complete / failed).
        updateTransferRate(m.transfer);
        // Coalesce UI rebuilds: a stuck/retrying transfer can fire
        // many events per second, and rebuilding the chat DOM each
        // time causes visible flicker. Once-per-frame is plenty.
        scheduleRenderTransfers();
        scheduleRenderMessages();
        scheduleRenderTransferHeaderPill();  // v0.8.8 aggregate pill
        // v0.9.1: terminal transfers feed the activity timeline.
        if (m.transfer.status === "complete" || m.transfer.status === "failed") {
          scheduleActivityRefresh();
        }
        if (state.activePane === "files" && state.filesMode === "sent") {
          scheduleRenderFilesPanel();
        }
        scheduleRefreshStatus();
      }
    };
    ws.onclose = () => { try { LiveRefresh.onClose(); } catch (e) { console.warn(e); } };
    ws.onerror = () => { try { ws.close(); } catch {} };
  }

