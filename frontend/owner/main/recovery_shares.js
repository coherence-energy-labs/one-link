  // ── recovery wizard: HELD-SHARES card (guardian side of social) ─
  // The third path of recovery. When user X distributes Shamir
  // shares of their identity, the guardians (other users) get
  // .olss files. This card lets a guardian import those files
  // into their daemon so they can be unwrapped + delivered back
  // when X needs to recover. Local-only flow: the guardian decides
  // how to deliver (in person, USB, email).
  async function _recwizRenderHeldSharesCard() {
    const card = document.getElementById("recwiz-track-held-shares");
    if (!card) return;
    let res = null;
    try { res = await api.recoveryHeldSharesList(); } catch (_) { /* ignore */ }
    const shares = (res && res.shares) || [];
    const count = shares.length;
    const pillCls = count > 0 ? "ready" : "unavailable";
    const pillText = count > 0
      ? `${count} share${count === 1 ? "" : "s"} held`
      : "None held";
    const list = count > 0 ? `
      <div class="recwiz-shares" style="margin-top:10px;">
        ${shares.map((s) => {
          const meta = s.label
            ? escapeText(s.label)
            : `share ${s.share_index} of ${s.total_n} (threshold ${s.threshold_k})`;
          return `
            <div class="recwiz-share-row">
              <span class="recwiz-share-num">#${s.share_index}/${s.total_n}</span>
              <span class="recwiz-share-name">${meta}</span>
              <button type="button" class="recwiz-btn"
                      data-recwiz-share-unwrap="${s.id}"
                      title="Unwrap this share so you can deliver the bytes back to the owner">Unwrap</button>
              <button type="button" class="recwiz-btn recwiz-btn-danger"
                      data-recwiz-share-drop="${s.id}" title="Forget this share">Forget</button>
            </div>`;
        }).join("")}
      </div>` : "";
    card.innerHTML = `
      <div class="recwiz-card-head">
        <div class="recwiz-card-name">Recovery shares you hold for others</div>
        <div class="recwiz-card-status ${pillCls}">${escapeText(pillText)}</div>
      </div>
      <p class="recwiz-card-desc">
        If someone sent you a recovery share (a small .olss file)
        for safekeeping, import it here. Your daemon stores it
        encrypted to your key; only you can unwrap it when they
        need help recovering.
      </p>
      <details class="recwiz-help">
        <summary>How does this work?</summary>
        <p>
          When a friend sets up social-share recovery, they split
          their identity into pieces and seal each piece to one
          trusted contact's key. You are one of those contacts.
          The .olss file you received is your piece, sealed so only
          you can open it. When your friend needs to recover (e.g.,
          lost their phone), you import this share, your daemon
          unwraps it with your identity, and you deliver the raw
          bytes back to them via whatever you trust (in person,
          encrypted email, USB stick). Their daemon collects K
          such pieces from K different friends and reconstructs
          their identity.
        </p>
      </details>
      ${list}
      <div class="recwiz-card-actions" style="margin-top:10px;">
        <button type="button" class="recwiz-btn recwiz-btn-primary"
                data-recwiz-held="import">
          Import a share file
        </button>
      </div>
      <div class="recwiz-card-body" hidden></div>
    `;
    card.querySelector('[data-recwiz-held="import"]')
      .addEventListener("click", () => _recwizHeldSharesImportStart());
    card.querySelectorAll('[data-recwiz-share-drop]').forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = Number(btn.getAttribute("data-recwiz-share-drop"));
        _recwizHeldShareDrop(id);
      });
    });
    card.querySelectorAll('[data-recwiz-share-unwrap]').forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = Number(btn.getAttribute("data-recwiz-share-unwrap"));
        _recwizHeldShareUnwrap(id);
      });
    });
  }

  async function _recwizHeldShareUnwrap(id) {
    let res;
    try {
      res = await api.recoveryHeldSharesUnwrap(id);
    } catch (e) {
      toast(`Unwrap failed: ${errorToastBody(e)}`, "bad", 6000);
      return;
    }
    if (!res || !res.ok) {
      toast(`Unwrap failed: ${(res && res.error) || "unknown"}`, "bad", 6000);
      return;
    }
    // Build a small modal showing the unwrapped (idx, bytes) for
    // the user to copy + manually deliver. Reuses the recwiz-modal
    // shell + a copy button.
    let modal = document.getElementById("held-share-unwrap-modal");
    if (!modal) {
      modal = document.createElement("div");
      modal.id = "held-share-unwrap-modal";
      modal.className = "recwiz-modal";
      modal.setAttribute("role", "dialog");
      modal.setAttribute("aria-modal", "true");
      modal.setAttribute("aria-label", "Unwrapped recovery share");
      modal.innerHTML = `
        <div class="recwiz-backdrop" data-held-share-close></div>
        <div class="recwiz-pane">
          <h2 class="recwiz-title">Unwrapped recovery share</h2>
          <div class="recwiz-share-unwrap-body"></div>
        </div>
      `;
      document.body.appendChild(modal);
      modal.addEventListener("click", (ev) => {
        const t = ev.target;
        if (!(t instanceof Element)) return;
        if (t.hasAttribute("data-held-share-close")) {
          modal.classList.remove("show");
          document.body.classList.remove("recwiz-open");
        }
      });
    }
    const payload = `${res.share_index}:${res.share_bytes_b64}`;
    const body = modal.querySelector(".recwiz-share-unwrap-body");
    body.innerHTML = `
      <p class="recwiz-lead">
        Share #${res.share_index} of ${res.total_n} (threshold
        ${res.threshold_k}). The owner needs ${res.threshold_k}
        such pieces from ${res.threshold_k} different guardians to
        recover.
      </p>
      <p class="recwiz-warn">
        Deliver these bytes to the owner via whatever you trust
        (in person, encrypted email, USB). They paste it into
        their recovery flow. Anyone who collects ${res.threshold_k}
        such pieces can reconstruct the owner's identity, so
        treat this with the same care you would the owner's
        actual recovery phrase.
      </p>
      <textarea class="recwiz-phrase-input" readonly aria-label="Unwrapped share payload"
                style="min-height:80px;">${escapeText(payload)}</textarea>
      <p class="recwiz-card-meta">Format: <code>share_index:base64_share_bytes</code></p>
      <div class="recwiz-card-actions" style="justify-content:flex-end;">
        <button type="button" class="recwiz-btn" id="recwiz-share-copy">Copy</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" data-held-share-close>Done</button>
      </div>
    `;
    body.querySelector("#recwiz-share-copy").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(payload);
        toast("Copied to clipboard.", "good", 3000);
      } catch (e) {
        toast(`Could not copy: ${e.message || e}`, "bad", 5000);
      }
    });
    modal.classList.add("show");
    document.body.classList.add("recwiz-open");
  }

  function _recwizHeldSharesImportStart() {
    const card = document.getElementById("recwiz-track-held-shares");
    const body = card.querySelector(".recwiz-card-body");
    body.hidden = false;
    card.classList.add("open");
    body.innerHTML = `
      <p class="recwiz-card-desc">
        Pick the .olss file. Optionally add a label so future-you
        remembers who sent it.
      </p>
      <input type="file" id="recwiz-held-file" accept=".olss"
             aria-label="Recovery share file" />
      <p class="recwiz-card-meta" id="recwiz-held-info" style="margin:6px 0;"></p>
      <div class="recwiz-verify-row" style="flex-direction:column;align-items:stretch;gap:6px;">
        <label for="recwiz-held-label" style="min-width:0;color:var(--text);">
          Label (optional)
        </label>
        <input type="text" id="recwiz-held-label" class="recwiz-verify-input"
               maxlength="200"
               placeholder="e.g. Alice's recovery share #3" />
      </div>
      <p class="recwiz-feedback" id="recwiz-held-fb"></p>
      <div class="recwiz-card-actions">
        <button type="button" class="recwiz-btn" data-recwiz-held="hide">Cancel</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" id="recwiz-held-submit" disabled>
          Import share
        </button>
      </div>
    `;
    const file = body.querySelector("#recwiz-held-file");
    const info = body.querySelector("#recwiz-held-info");
    const labelInput = body.querySelector("#recwiz-held-label");
    const submit = body.querySelector("#recwiz-held-submit");
    const fb = body.querySelector("#recwiz-held-fb");
    file.addEventListener("change", () => {
      const f = file.files && file.files[0];
      info.textContent = f ? `${f.name} (${_recwizHumanSize(f.size)})` : "";
      submit.disabled = !f;
    });
    body.querySelector('[data-recwiz-held="hide"]').addEventListener("click", () => {
      body.hidden = true; card.classList.remove("open"); body.innerHTML = "";
    });
    submit.addEventListener("click", async () => {
      const f = file.files && file.files[0];
      if (!f) return;
      submit.disabled = true;
      fb.className = "recwiz-feedback";
      fb.textContent = "Reading file...";
      let b64;
      try { b64 = await _recwizFileToB64(f); }
      catch (e) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = `Could not read file: ${e.message || e}`;
        submit.disabled = false;
        return;
      }
      fb.textContent = "Importing...";
      try {
        await api.recoveryHeldSharesImport(
          b64, labelInput.value.trim() || null, null,
        );
        toast("Share imported.", "good", 4000);
        body.hidden = true; card.classList.remove("open"); body.innerHTML = "";
        await _recwizRenderHeldSharesCard();
      } catch (e) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = errorToastBody(e) || "Import failed.";
        submit.disabled = false;
      }
    });
    setTimeout(() => file.focus(), 60);
  }

  async function _recwizHeldShareDrop(id) {
    const ok = window.confirm(
      "Forget this recovery share?\n\n" +
      "Once forgotten you cannot help the owner recover with this " +
      "share. If they later ask for help, you will have to import " +
      "the share file again (if you still have it)."
    );
    if (!ok) return;
    try {
      await api.recoveryHeldSharesDelete(id);
      toast("Share forgotten.", "info", 3000);
      await _recwizRenderHeldSharesCard();
    } catch (e) {
      toast(`Drop failed: ${errorToastBody(e)}`, "bad", 5000);
    }
  }

