  // ── recovery wizard: SOCIAL track ───────────────────────────────
  function _recwizRenderSocialCard(s) {
    const card = document.getElementById("recwiz-track-social");
    if (!card) return;
    const ready = !!s.ready;
    const avail = !!s.available;
    let status, cls;
    if (ready) {
      status = `${s.threshold_k} of ${s.guardian_count} ready`;
      cls = "ready";
    } else if (!avail) {
      status = "Need 2+ contacts";
      cls = "unavailable";
    } else {
      status = "Not set up";
      cls = "partial";
    }
    const meta = ready
      ? `Issued ${_recwizFormatRelative(s.last_action_at_ms)}. Any ${s.threshold_k} of ${s.guardian_count} guardians can help you recover.`
      : "";
    const btnLabel = ready ? "Re-issue shares" : "Pick guardians";
    const disabled = avail ? "" : "disabled";
    card.innerHTML = `
      <div class="recwiz-card-head">
        <div class="recwiz-card-name">Trusted contacts</div>
        <div class="recwiz-card-status ${cls}">${escapeText(status)}</div>
      </div>
      <p class="recwiz-card-desc">
        Split your recovery into shares and hand them to people you trust.
        Any 3 of 5 (or whatever you pick) can help you back in. No single
        contact can do it alone.
      </p>
      <details class="recwiz-help">
        <summary>How does this work?</summary>
        <p>
          Your secret gets mathematically split into N pieces with a
          threshold K. Any K of those pieces can reconstruct the
          secret; K-1 pieces are useless. Each piece is sealed to the
          guardian you give it to, so a leaked piece is unreadable to
          anyone except that one guardian. If you ever need to
          recover, you contact K of your guardians and they help you
          back in. No single guardian (and no central service) can
          lock you out.
        </p>
      </details>
      ${meta ? `<p class="recwiz-card-meta">${escapeText(meta)}</p>` : ""}
      ${!avail ? `<p class="recwiz-feedback">Pair at least 2 trusted devices or people before you can use this track.</p>` : ""}
      <div class="recwiz-card-actions">
        <button type="button" class="recwiz-btn recwiz-btn-primary" data-recwiz-social="open" ${disabled}>
          ${btnLabel}
        </button>
        ${ready
          ? `<button type="button" class="recwiz-btn" data-recwiz-social="test">Test my shares</button>`
          : ""}
      </div>
      <div class="recwiz-card-body" hidden></div>
    `;
    const btn = card.querySelector('[data-recwiz-social="open"]');
    if (btn && !disabled) btn.addEventListener("click", () => _recwizSocialOpen());
    const testBtn = card.querySelector('[data-recwiz-social="test"]');
    if (testBtn) testBtn.addEventListener("click", () => _recwizSocialTestStart());
  }

  function _recwizSocialTestStart() {
    const card = document.getElementById("recwiz-track-social");
    const body = card.querySelector(".recwiz-card-body");
    body.hidden = false;
    card.classList.add("open");
    body.innerHTML = `
      <p class="recwiz-help-text">
        Paste any K (or more) unwrapped shares your guardians sent
        back. We'll combine them in memory and confirm they still
        reconstruct your current identity. Nothing is written to
        disk; this never replaces or restores anything.
      </p>
      <p class="recwiz-help-text" style="opacity:0.7;">
        Each line: <code>index:base64-share-bytes</code>
      </p>
      <textarea class="recwiz-phrase-input" id="recwiz-social-test-ta"
                aria-label="Unwrapped guardian shares"
                rows="5" placeholder="1:base64...\n3:base64..."
                spellcheck="false" autocapitalize="off"></textarea>
      <p class="recwiz-feedback" id="recwiz-social-test-fb"></p>
      <div class="recwiz-card-actions">
        <button type="button" class="recwiz-btn" data-recwiz-social="test-hide">Hide</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" id="recwiz-social-test-submit" disabled>
          Verify shares
        </button>
      </div>
    `;
    const ta = body.querySelector("#recwiz-social-test-ta");
    const fb = body.querySelector("#recwiz-social-test-fb");
    const submit = body.querySelector("#recwiz-social-test-submit");
    function refresh() {
      const lines = ta.value.split("\n").filter(l => l.trim().includes(":"));
      submit.disabled = lines.length < 2;
    }
    ta.addEventListener("input", refresh);
    refresh();
    body.querySelector('[data-recwiz-social="test-hide"]')
      .addEventListener("click", () => {
        body.hidden = true;
        body.innerHTML = "";
        card.classList.remove("open");
      });
    submit.addEventListener("click", async () => {
      submit.disabled = true;
      fb.className = "recwiz-feedback";
      fb.textContent = "Verifying...";
      let res;
      try {
        res = await api.recoverySharesTest({ shareLines: ta.value });
      } catch (e) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = errorToastBody(e);
        submit.disabled = false;
        return;
      }
      if (!res.valid_recovery) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = res.error || "Shares didn't reconstruct a valid recovery.";
        submit.disabled = false;
        return;
      }
      if (!res.has_current_identity) {
        fb.className = "recwiz-feedback";
        fb.textContent = "Valid quorum (" + res.share_count + " shares), but this device has no identity to compare against.";
      } else if (res.matches_current_identity) {
        fb.className = "recwiz-feedback ok";
        fb.textContent = "Verified. These " + res.share_count + " shares reconstruct your current identity.";
      } else {
        fb.className = "recwiz-feedback bad";
        fb.textContent = "Valid quorum, but it reconstructs a DIFFERENT identity. These shares are from someone else's recovery setup.";
      }
      submit.disabled = false;
    });
  }

  async function _recwizSocialOpen() {
    const card = document.getElementById("recwiz-track-social");
    const body = card.querySelector(".recwiz-card-body");
    body.hidden = false;
    card.classList.add("open");
    body.innerHTML = `<p class="recwiz-feedback">Loading your trusted contacts...</p>`;
    let resp;
    try {
      resp = await api.recoverySocialCandidates();
    } catch (e) {
      body.innerHTML = `<p class="recwiz-feedback bad">${escapeText(errorToastBody(e))}</p>`;
      return;
    }
    const candidates = resp.candidates || [];
    if (candidates.length < 2) {
      body.innerHTML = `<p class="recwiz-feedback bad">You need at least 2 pinned contacts before you can use this track. Pair more devices or people first.</p>`;
      return;
    }
    const initialChecked = Math.min(candidates.length, resp.recommended_total_n || 5);
    const initialK = Math.min(
      resp.recommended_threshold_k || 3,
      Math.max(2, initialChecked),
    );
    const rows = candidates.map((c, i) => `
      <label class="recwiz-guardian-item">
        <input type="checkbox" data-recwiz-guardian="${escapeAttr(c.id)}"
               aria-label="${escapeAttr(c.label)} guardian"
               data-recwiz-guardian-label="${escapeAttr(c.label)}"
               data-recwiz-guardian-pub="${escapeAttr(c.pubkey_b64)}"
               ${i < initialChecked ? "checked" : ""} />
        <span class="recwiz-guardian-label">${escapeText(c.label)}</span>
        <span class="recwiz-guardian-meta">${c.verified ? "verified" : "trusted"}</span>
      </label>`).join("");
    body.innerHTML = `
      <p class="recwiz-card-desc">
        Pick the people who will help you recover. The share each
        guardian receives is sealed to their device key: a leaked
        share file is useless to anyone but that guardian.
      </p>
      <div class="recwiz-guardian-list" role="list">${rows}</div>
      <div class="recwiz-threshold-row">
        <span>Need</span>
        <input type="number" id="recwiz-threshold" class="recwiz-threshold-input"
               aria-label="Guardian shares required to recover"
               min="2" value="${initialK}" />
        <span>of <span id="recwiz-guardian-count">${initialChecked}</span> to recover</span>
      </div>
      <p class="recwiz-feedback" id="recwiz-social-fb"></p>
      <div class="recwiz-card-actions">
        <button type="button" class="recwiz-btn" data-recwiz-social="hide">Cancel</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" data-recwiz-social="issue">
          Generate shares
        </button>
      </div>
    `;
    const checkboxes = Array.from(body.querySelectorAll('input[data-recwiz-guardian]'));
    const thresholdInput = body.querySelector("#recwiz-threshold");
    const countSpan = body.querySelector("#recwiz-guardian-count");
    function recount() {
      const n = checkboxes.filter((c) => c.checked).length;
      countSpan.textContent = String(n);
      let cur = Number(thresholdInput.value || 0);
      if (cur > n) cur = Math.max(2, n);
      if (cur < 2) cur = Math.min(2, n);
      thresholdInput.value = String(cur);
      thresholdInput.max = String(Math.max(2, n));
    }
    checkboxes.forEach((c) => c.addEventListener("change", recount));
    recount();
    body.querySelector('[data-recwiz-social="hide"]').addEventListener("click", () => {
      body.hidden = true; card.classList.remove("open"); body.innerHTML = "";
    });
    body.querySelector('[data-recwiz-social="issue"]')
      .addEventListener("click", () => _recwizSocialIssue(body));
  }

  async function _recwizSocialIssue(body) {
    const fb = body.querySelector("#recwiz-social-fb");
    const selected = Array.from(body.querySelectorAll('input[data-recwiz-guardian]:checked'))
      .map((c) => ({
        label: c.getAttribute("data-recwiz-guardian-label"),
        pubkey_b64: c.getAttribute("data-recwiz-guardian-pub"),
      }));
    const thresholdK = Number(body.querySelector("#recwiz-threshold").value || 3);
    if (selected.length < 2) {
      fb.className = "recwiz-feedback bad";
      fb.textContent = "Pick at least 2 guardians.";
      return;
    }
    if (thresholdK < 2 || thresholdK > selected.length) {
      fb.className = "recwiz-feedback bad";
      fb.textContent = `Threshold must be 2 to ${selected.length}.`;
      return;
    }
    fb.className = "recwiz-feedback";
    fb.textContent = "Generating sealed shares...";
    const issueBtn = body.querySelector('[data-recwiz-social="issue"]');
    issueBtn.disabled = true;
    let resp;
    try {
      resp = await api.recoverySocialIssue(selected, thresholdK);
    } catch (e) {
      fb.className = "recwiz-feedback bad";
      fb.textContent = `Could not generate shares: ${errorToastBody(e)}`;
      issueBtn.disabled = false;
      return;
    }
    const shareRows = resp.shares.map((s) => `
      <div class="recwiz-share-row">
        <span class="recwiz-share-num">#${s.share_index}/${s.total_n}</span>
        <span class="recwiz-share-name">${escapeText(s.guardian_label)}</span>
        <button type="button" class="recwiz-btn" data-recwiz-share-dl="${s.share_index}">Download</button>
      </div>`).join("");
    body.innerHTML = `
      <p class="recwiz-card-desc">
        Your shares are ready. Download each one and deliver it to its
        guardian via whatever you trust (USB stick, in person, encrypted
        email). Each share is sealed to that specific guardian.
      </p>
      <div class="recwiz-shares">${shareRows}</div>
      <p class="recwiz-warn">
        Threshold: any ${resp.threshold_k} of ${resp.guardian_count} can
        help you recover. Keep track of who holds which share number.
        If you forget, your only path back is to ask every guardian.
      </p>
      <div class="recwiz-card-actions">
        <button type="button" class="recwiz-btn" data-recwiz-social="downloadAll">Download all</button>
        <button type="button" class="recwiz-btn" data-recwiz-social="done">Done</button>
      </div>
    `;
    const shares = resp.shares || [];
    shares.forEach((s) => {
      const b = body.querySelector(`[data-recwiz-share-dl="${s.share_index}"]`);
      if (b) b.addEventListener("click", () => _recwizDownloadShare(s));
    });
    body.querySelector('[data-recwiz-social="downloadAll"]').addEventListener("click", () => {
      shares.forEach((s, i) => setTimeout(() => _recwizDownloadShare(s), i * 250));
    });
    body.querySelector('[data-recwiz-social="done"]').addEventListener("click", async () => {
      body.hidden = true;
      document.getElementById("recwiz-track-social").classList.remove("open");
      body.innerHTML = "";
      await _recwizRefreshStatus();
      await refreshOneSetup();
    });
    await _recwizRefreshStatus();
  }

  function _recwizDownloadShare(share) {
    const raw = String(share.blob_b64u || "");
    const b64 = raw.replace(/-/g, "+").replace(/_/g, "/");
    const pad = (4 - (b64.length % 4)) % 4;
    const padded = b64 + "=".repeat(pad);
    let bytes;
    try {
      bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    } catch (e) {
      toast(`Share download failed: ${e.message || e}`, "bad", 5000);
      return;
    }
    const blob = new Blob([bytes], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = share.filename || `one-link-share-${share.share_index}.olss`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

