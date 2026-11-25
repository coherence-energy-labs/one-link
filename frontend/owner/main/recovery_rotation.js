  // ── recovery wizard: ROTATE-identity card + modal ──────────────
  // Mint a fresh identity, sign a cert with the OLD key, queue
  // per-peer delivery. The peer-side handler atomically migrates
  // its pinned record so the user's friends keep recognizing them
  // without manual re-pair. Backend journals the signed cert + complete peer
  // snapshot without touching live authority. Restart installs the identity
  // and atomically lands every row in pending_rotation_announcements;
  // outbound delivery then happens on the next CAPS handshake to each peer.
  async function _recwizRenderRotateCard() {
    const card = document.getElementById("recwiz-track-rotate");
    if (!card) return;
    let status = null;
    try { status = await api.recoveryRotateStatus(); } catch (e) { /* ignore */ }
    const summary = (status && status.summary) || { total: 0, pending: 0, acked: 0 };
    const rows = (status && status.rows) || [];
    const staged = status && status.staged_rotation && status.staged_rotation.pending
      ? status.staged_rotation : null;
    const stagedError = staged && staged.error ? staged.error : "";
    const inFlight = summary.total > 0 || !!staged;
    const pillCls = staged ? "partial" : !inFlight
      ? "unavailable"
      : summary.pending === 0 ? "ready" : "partial";
    const pillText = stagedError
      ? "Journal needs attention"
      : staged
      ? "Staged — restart required"
      : !inFlight
      ? "Idle"
      : `${summary.acked} of ${summary.total} acked`;
    const meta = stagedError
      ? "The staged rotation journal could not be verified. Current live identity remains active; check daemon logs and do not assume the rotation will commit."
      : staged
      ? `Signed rotation durably staged for ${staged.staged_peer_count || 0} paired peer${staged.staged_peer_count === 1 ? "" : "s"}. Current live keys and queues are unchanged until restart.`
      : inFlight && summary.pending > 0
      ? `${summary.pending} peer${summary.pending === 1 ? "" : "s"} still need to receive your new key.`
      : (inFlight ? "All paired peers have received and applied your new key." : "");
    // Surface the daemon's current identity fingerprint so a user
    // who just rotated can visually verify the identity actually
    // changed (or so a user mid-debug can spot which install they're
    // running). Truncate to 16 hex chars (8 bytes) - enough that
    // collisions are vanishingly unlikely while staying readable.
    const myFp = state.me?.fingerprint || "";
    const fpShort = myFp ? `${myFp.slice(0, 16)}…` : "(unknown)";
    const fpRow = myFp
      ? `<p class="recwiz-card-meta" style="font-family:var(--mono); margin:4px 0 8px;">
           Current identity: <span style="color:var(--text);">${escapeText(fpShort)}</span>
         </p>`
      : "";
    // Per-peer ack list: render each pending/acked row so the user
    // can see exactly who is up-to-date. Sorted: pending first
    // (the action items), then acked (the wins).
    const sortedRows = rows.slice().sort((a, b) => {
      const aAcked = a.acked_ms ? 1 : 0;
      const bAcked = b.acked_ms ? 1 : 0;
      if (aAcked !== bAcked) return aAcked - bAcked;  // pending first
      return (b.queued_ms || 0) - (a.queued_ms || 0);  // newest first
    });
    const peerListHtml = summary.total > 0 ? `
      <div class="recwiz-shares" style="margin-top:10px;">
        ${sortedRows.map((r) => {
          const acked = !!r.acked_ms;
          const ackBadge = acked
            ? `<span style="color:#2ec489;">acked ${escapeText(_recwizFormatRelative(r.acked_ms))}</span>`
            : (r.attempt_count > 0
                ? `<span style="color:var(--text-dim);">pending, ${r.attempt_count} attempt${r.attempt_count === 1 ? "" : "s"}</span>`
                : `<span style="color:var(--text-dim);">pending, awaiting next contact</span>`);
          return `
            <div class="recwiz-share-row">
              <span class="recwiz-share-name">${escapeText(r.peer_label || r.peer_fp.slice(0, 8))}</span>
              <span class="recwiz-guardian-meta" style="text-align:right;">${ackBadge}</span>
            </div>`;
        }).join("")}
      </div>` : "";
    card.innerHTML = `
      <div class="recwiz-card-head">
        <div class="recwiz-card-name">Change your identity key</div>
        <div class="recwiz-card-status ${pillCls}">${escapeText(pillText)}</div>
      </div>
      ${fpRow}
      <p class="recwiz-card-desc">
        Replace this device's identity with a fresh one. Useful if
        you think someone got hold of your old key, or if a device
        was lost. Your paired devices will recognize the new key
        automatically the next time they talk to you - you don't
        need to re-pair.
      </p>
      <details class="recwiz-help">
        <summary>How does this work?</summary>
        <p>
          Your daemon generates a fresh identity key and signs a
          small certificate with the OLD key that authorizes the
          change. That certificate is the cryptographic proof: only
          someone who held the old key could have produced it. The
          daemon durably stages the certificate and paired-peer snapshot.
          On restart it installs the new key and atomically queues every
          announcement. When this device next talks to each peer, the
          certificate goes along with the normal handshake. The peer
          verifies the signature against their pinned old key,
          atomically migrates their record so your alias, mute,
          verified state, and chat history all follow you to the
          new key, and sends an ack back so this card can show
          which peers are up to date.
        </p>
      </details>
      ${meta ? `<p class="recwiz-card-meta">${escapeText(meta)}</p>` : ""}
      ${peerListHtml}
      <div class="recwiz-card-actions" style="margin-top:10px;">
        ${staged ? "" : `<button type="button" class="recwiz-btn" data-recwiz-action="open-rotate">
          ${inFlight ? "Change again" : "Change identity key"}
        </button>`}
        ${staged && !stagedError && staged.new_fp ? `<button type="button" class="recwiz-btn" data-recwiz-rotate-phrase="1">Show new recovery words</button>` : ""}
        ${staged && !stagedError ? `<button type="button" class="recwiz-btn" data-recwiz-rotate-restart="1">Shut down One Link now</button>` : ""}
        ${inFlight ? `<button type="button" class="recwiz-btn" data-recwiz-rotate-refresh="1">Refresh status</button>` : ""}
      </div>
    `;
    const refresh = card.querySelector('[data-recwiz-rotate-refresh="1"]');
    if (refresh) {
      refresh.addEventListener("click", () => _recwizRenderRotateCard());
    }
    const showPhrase = card.querySelector('[data-recwiz-rotate-phrase="1"]');
    if (showPhrase) {
      showPhrase.addEventListener("click", () => (
        _recwizShowPendingRotationPhrase(staged.new_fp)
      ));
    }
    const restart = card.querySelector('[data-recwiz-rotate-restart="1"]');
    if (restart) {
      restart.addEventListener("click", () => _recwizShutdownDaemon("rotation_restart"));
    }
  }

  async function openRotationModal() {
    _ensureRotationModal();
    const modal = document.getElementById("recovery-rotate-modal");
    _recwizCaptureFocus(modal);
    modal.classList.add("show");
    document.body.classList.add("recwiz-open");
    _renderRotationModalIntro();
    _recwizSetInitialFocus(modal);
  }

  function _closeRotationModal() {
    const modal = document.getElementById("recovery-rotate-modal");
    if (modal) modal.classList.remove("show");
    document.body.classList.remove("recwiz-open");
    _recwizReturnFocus(modal);
  }

  function _ensureRotationModal() {
    if (document.getElementById("recovery-rotate-modal")) return;
    const m = document.createElement("div");
    m.id = "recovery-rotate-modal";
    m.className = "recwiz-modal";
    m.setAttribute("role", "dialog");
    m.setAttribute("aria-modal", "true");
    m.setAttribute("aria-label", "Change identity key");
    m.innerHTML = `
      <div class="recwiz-backdrop" data-recwiz-close></div>
      <div class="recwiz-pane">
        <h2 class="recwiz-title">Change your identity key</h2>
        <p class="recwiz-lead">
          This prepares a new secret this device will use to prove it's you.
          The current identity stays live until you restart One Link.
          Your paired devices will recognize the new one automatically
          the next time you talk to them. You don't need to re-pair.
        </p>
        <details class="recwiz-help" style="margin-bottom:14px;">
          <summary>How does this work?</summary>
          <p>
            Your daemon generates a fresh identity key and signs a
            small certificate with the OLD key that authorizes the
            change. That certificate is the cryptographic proof:
            only someone who held the old key could have produced
            it. The daemon durably stages the certificate and paired-peer
            snapshot. On restart it installs the new key and atomically queues
            every announcement. When this device next talks to each
            peer, the certificate goes along with the normal
            handshake. The peer verifies the signature against
            their pinned old key, atomically migrates their record
            so your alias, mute, verified state, and chat history
            all follow you to the new key, and sends an ack back
            so the rotation card shows which peers are up to date.
          </p>
        </details>
        <div class="recwiz-rotate-body"></div>
      </div>
    `;
    document.body.appendChild(m);
    m.addEventListener("click", (ev) => {
      const t = ev.target;
      if (!(t instanceof Element)) return;
      if (t.hasAttribute("data-recwiz-close")) _closeRotationModal();
      if (t.getAttribute("data-recwiz-action") === "close-rotate") {
        _closeRotationModal();
      }
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && m.classList.contains("show")) {
        _closeRotationModal();
      }
    });
  }

  function _renderRotationModalIntro() {
    const modal = document.getElementById("recovery-rotate-modal");
    const body = modal.querySelector(".recwiz-rotate-body");
    body.innerHTML = `
      <div class="recwiz-danger-box">
        <strong>This is a security action.</strong>
        After staging, you will get a NEW 24-word recovery phrase.
        You must write it down on paper. The old phrase remains current until
        restart; after restart it no longer recovers the new identity.
        Unpaired peers (people you have
        not yet trusted) will see your new key as a stranger and
        need to be added again.
      </div>
      <div class="recwiz-verify-row" style="flex-direction:column; align-items:stretch; gap:6px;">
        <label for="recwiz-rotate-reason" style="min-width:0; color:var(--text);">
          Why are you rotating?
        </label>
        <select id="recwiz-rotate-reason" class="recwiz-verify-input">
          <option value="scheduled">Scheduled rotation (defense in depth)</option>
          <option value="compromise">My key may be compromised</option>
          <option value="device_lost">A device with this key was lost</option>
          <option value="other">Other reason</option>
        </select>
      </div>
      <label class="recwiz-confirm-row">
        <input type="checkbox" id="recwiz-rotate-confirm" />
        <span>I understand my current identity will be replaced + I will write down the new phrase.</span>
      </label>
      <p class="recwiz-feedback" id="recwiz-rotate-fb"></p>
      <div class="recwiz-card-actions" style="justify-content:flex-end;">
        <button type="button" class="recwiz-btn" data-recwiz-action="close-rotate">Cancel</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" id="recwiz-rotate-submit" disabled>
          Rotate now
        </button>
      </div>
    `;
    const confirmBox = body.querySelector("#recwiz-rotate-confirm");
    const submit = body.querySelector("#recwiz-rotate-submit");
    confirmBox.addEventListener("change", () => {
      submit.disabled = !confirmBox.checked;
    });
    submit.addEventListener("click", () => _recwizRotateSubmit());
  }

  function _recwizRenderRotationPhrase(res) {
    const modal = document.getElementById("recovery-rotate-modal");
    const body = modal.querySelector(".recwiz-rotate-body");
    const words = Array.isArray(res.new_words) ? res.new_words : [];
    if (words.length !== 24 || words.some((word) => typeof word !== "string")) {
      body.innerHTML = `<p class="recwiz-feedback bad">The daemon returned an invalid recovery phrase. Do not restart; refresh status and try showing the words again.</p>`;
      return false;
    }
    const wordCells = words.map((w, i) => (
      `<span class="recwiz-word"><span class="recwiz-word-num">${i + 1}.</span>${escapeText(w)}</span>`
    )).join("");
    body.innerHTML = `
      <div class="recwiz-restart-card">
        <strong>Identity rotation staged.</strong>
        Your new 24-word recovery phrase is below. Write it down on
        paper. Anyone with these words can be you on a fresh install.
        <br><br>
        ${escapeText(`Signed announcements are durably staged for ${res.staged_peer_count || 0} paired peer${res.staged_peer_count === 1 ? "" : "s"}. No live key or queue changed yet.`)}
        Restart One Link now to atomically install the new identity and queue every announcement.
      </div>
      <div class="recwiz-words" aria-label="24 word recovery phrase">${wordCells}</div>
      <div class="recwiz-card-actions" style="justify-content:flex-end;">
        <button type="button" class="recwiz-btn" data-recwiz-rotate="print">Print</button>
        <button type="button" class="recwiz-btn" data-recwiz-rotate="restart">Shut down One Link now</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" data-recwiz-action="close-rotate">Close</button>
      </div>
    `;
    body.querySelector('[data-recwiz-rotate="print"]')
      .addEventListener("click", () => _recwizPhrasePrint(words));
    body.querySelector('[data-recwiz-rotate="restart"]')
      .addEventListener("click", () => _recwizShutdownDaemon("rotation_restart"));
    return true;
  }

  async function _recwizShowPendingRotationPhrase(expectedNewFp) {
    if (!window.confirm(
      "Show the staged identity's secret recovery words?\n\n" +
      "Anyone who sees these words can become this identity."
    )) return;
    let res;
    try {
      res = await api.recoveryRotatePendingPhrase(expectedNewFp);
    } catch (e) {
      toast(`Could not show staged words: ${errorToastBody(e)}`, "bad", 6000);
      return;
    }
    _ensureRotationModal();
    const modal = document.getElementById("recovery-rotate-modal");
    _recwizCaptureFocus(modal);
    modal.classList.add("show");
    document.body.classList.add("recwiz-open");
    if (_recwizRenderRotationPhrase(res)) _recwizSetInitialFocus(modal);
  }

  async function _recwizRotateSubmit() {
    const modal = document.getElementById("recovery-rotate-modal");
    const body = modal.querySelector(".recwiz-rotate-body");
    const reason = body.querySelector("#recwiz-rotate-reason").value;
    const fb = body.querySelector("#recwiz-rotate-fb");
    const submit = body.querySelector("#recwiz-rotate-submit");
    submit.disabled = true;
    fb.className = "recwiz-feedback";
    fb.textContent = "Generating, signing, and durably staging the new identity...";
    let res;
    try {
      res = await api.recoveryRotate(reason);
    } catch (e) {
      fb.className = "recwiz-feedback bad";
      fb.textContent = errorToastBody(e) || "Rotation failed.";
      submit.disabled = false;
      return;
    }
    if (!res || !res.ok) {
      fb.className = "recwiz-feedback bad";
      fb.textContent = (res && res.error) || "Rotation failed.";
      submit.disabled = false;
      return;
    }
    if (_recwizRenderRotationPhrase(res)) {
      toast(
        `Identity rotation staged for ${res.staged_peer_count || 0} peers. Restart One Link to commit it.`,
        "good", 6000,
      );
    }
  }

