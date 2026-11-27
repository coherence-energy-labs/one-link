  // ── recovery wizard: PHRASE track ───────────────────────────────
  function _recwizRenderPhraseCard(s) {
    const card = document.getElementById("recwiz-track-phrase");
    if (!card) return;
    const ready = !!s.ready;
    const avail = !!s.available;
    const needsPassphrase = !!s.requires_lockbox_passphrase;
    const status = ready
      ? "Verified"
      : needsPassphrase
        ? "Needs key migration"
        : avail ? "Not verified" : "Unavailable";
    const cls = ready ? "ready" : avail ? "partial" : "unavailable";
    const last = ready
      ? `Verified ${_recwizFormatRelative(s.last_action_at_ms)}.`
      : "";
    card.innerHTML = `
      <div class="recwiz-card-head">
        <div class="recwiz-card-name">Recovery phrase</div>
        <div class="recwiz-card-status ${cls}">${escapeText(status)}</div>
      </div>
      <p class="recwiz-card-desc">
        24 words on paper. The classic. Type them on a fresh install
        and your identity comes back.
      </p>
      <details class="recwiz-help">
        <summary>How does this work?</summary>
        <p>
          The 24 words encode the secret your One Link identity is
          derived from. Anyone who has those words can be you on a
          fresh install: your peers will recognize them as you, and
          saved history in a matching encrypted backup can be restored.
          Write the words on paper and keep that paper somewhere only
          you can reach. We cannot regenerate it for you.
        </p>
      </details>
      ${needsPassphrase ? `<p class="recwiz-feedback" style="color:#ffc400;">
        Legacy passphrase-protected application keys have not yet been
        seed-wrapped. Start One Link with the source ONE_LINK_PASSPHRASE,
        then export and test a new backup before treating phrase recovery
        as complete.</p>` : ""}
      ${last ? `<p class="recwiz-card-meta">${escapeText(last)}</p>` : ""}
      <div class="recwiz-card-actions">
        <button type="button" class="recwiz-btn recwiz-btn-primary" data-recwiz-phrase="show">
          ${ready ? "Show again" : "Show my 24 words"}
        </button>
        ${ready ? `<button type="button" class="recwiz-btn" data-recwiz-phrase="verify">Re-verify</button>` : ""}
        <button type="button" class="recwiz-btn" data-recwiz-phrase="test">Test my written phrase</button>
      </div>
      <div class="recwiz-card-body" hidden></div>
    `;
    card.querySelector('[data-recwiz-phrase="show"]')
      .addEventListener("click", () => _recwizPhraseShow());
    const reBtn = card.querySelector('[data-recwiz-phrase="verify"]');
    if (reBtn) reBtn.addEventListener("click", () => _recwizPhraseShow());
    card.querySelector('[data-recwiz-phrase="test"]')
      .addEventListener("click", () => _recwizPhraseStartTest());
  }

  // 'Test my written phrase' — non-destructive verify that the paper
  // backup matches this install's identity. The phrase pastes into a
  // textarea, posts to /api/v1/recovery/phrase/test, and renders a
  // green/amber/red status based on (valid_checksum + matches).
  function _recwizPhraseStartTest() {
    const card = document.getElementById("recwiz-track-phrase");
    const body = card.querySelector(".recwiz-card-body");
    body.hidden = false;
    card.classList.add("open");
    body.innerHTML = `
      <p class="recwiz-card-desc">
        Paste your 24 words below to check the paper backup. Nothing
        is written; the phrase never leaves this device.
      </p>
      <textarea class="recwiz-phrase-input" id="recwiz-phrase-test-input"
                aria-label="24 word recovery phrase to test"
                autocomplete="off" spellcheck="false"
                placeholder="abandon ability about ..."></textarea>
      <p class="recwiz-feedback" id="recwiz-phrase-test-fb"></p>
      <div class="recwiz-card-actions">
        <button type="button" class="recwiz-btn" data-recwiz-phrase="test-hide">Hide</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" id="recwiz-phrase-test-submit" disabled>
          Check phrase
        </button>
      </div>
    `;
    const ta = body.querySelector("#recwiz-phrase-test-input");
    const submit = body.querySelector("#recwiz-phrase-test-submit");
    const fb = body.querySelector("#recwiz-phrase-test-fb");
    ta.addEventListener("input", () => {
      const tokens = String(ta.value || "").trim().split(/\s+/).filter(Boolean);
      submit.disabled = tokens.length < 24;
      if (tokens.length === 0) {
        fb.className = "recwiz-feedback";
        fb.textContent = "";
      } else if (tokens.length < 24) {
        fb.className = "recwiz-feedback";
        fb.textContent = `${tokens.length} of 24 words.`;
      } else {
        fb.className = "recwiz-feedback";
        fb.textContent = "Ready to check.";
      }
    });
    body.querySelector('[data-recwiz-phrase="test-hide"]')
      .addEventListener("click", () => {
        body.hidden = true; card.classList.remove("open"); body.innerHTML = "";
      });
    submit.addEventListener("click", async () => {
      submit.disabled = true;
      fb.className = "recwiz-feedback";
      fb.textContent = "Checking...";
      let res;
      try {
        res = await api.recoveryPhraseTest(ta.value.trim());
      } catch (e) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = errorToastBody(e) || "Check failed.";
        submit.disabled = false;
        return;
      }
      if (!res.valid_checksum) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = `Not a valid 24-word phrase: ${res.error || "checksum failed"}.`;
        submit.disabled = false;
        return;
      }
      if (!res.has_current_identity) {
        fb.className = "recwiz-feedback good";
        fb.textContent = "Valid 24-word phrase. No current identity on this install to compare against.";
      } else if (res.requires_lockbox_passphrase) {
        fb.className = "recwiz-feedback";
        fb.style.color = "#ffc400";
        fb.textContent = "The phrase matches the master identity, but legacy application keys still require the source ONE_LINK_PASSPHRASE. Start with that passphrase and export a new backup before relying on paper-only recovery.";
      } else if (res.matches_current_identity) {
        fb.className = "recwiz-feedback good";
        fb.textContent = "Valid phrase and it matches this device's identity. Your paper backup is correct.";
      } else {
        fb.className = "recwiz-feedback";
        fb.style.color = "#ffc400";
        fb.textContent = "Valid 24-word phrase, but it does NOT match this device's identity. Check the paper against the phrase shown in the wizard.";
      }
      submit.disabled = false;
    });
    setTimeout(() => ta.focus(), 60);
  }

  async function _recwizPhraseShow() {
    const card = document.getElementById("recwiz-track-phrase");
    const body = card.querySelector(".recwiz-card-body");
    body.hidden = false;
    card.classList.add("open");
    body.innerHTML = `<p class="recwiz-feedback">Loading your phrase...</p>`;
    let resp;
    try {
      resp = await api.recoveryPhrase();
    } catch (e) {
      body.innerHTML = `<p class="recwiz-feedback bad">${escapeText("Could not load: " + errorToastBody(e))}</p>`;
      return;
    }
    const words = Array.isArray(resp?.words) ? resp.words : [];
    if (words.length !== 24) {
      body.innerHTML = `<p class="recwiz-feedback bad">Phrase did not contain 24 words.</p>`;
      return;
    }
    const wordCells = words.map((w, i) => (
      `<span class="recwiz-word"><span class="recwiz-word-num">${i + 1}.</span>${escapeText(w)}</span>`
    )).join("");
    body.innerHTML = `
      <p class="recwiz-warn">
        Anyone with these 24 words can be you on a fresh install.
        Write them on paper. Not a screenshot. Not a note app. Not
        the cloud. One Link does not store this phrase and cannot
        recover it for you.
      </p>
      <div class="recwiz-words" aria-label="24 word recovery phrase">${wordCells}</div>
      <div class="recwiz-card-actions">
        <button type="button" class="recwiz-btn" data-recwiz-phrase="print">Print</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" data-recwiz-phrase="verify-start">
          I wrote it down
        </button>
        <button type="button" class="recwiz-btn" data-recwiz-phrase="hide">Hide</button>
      </div>
    `;
    body.querySelector('[data-recwiz-phrase="print"]')
      .addEventListener("click", () => _recwizPhrasePrint(words));
    body.querySelector('[data-recwiz-phrase="verify-start"]')
      .addEventListener("click", () => _recwizPhraseStartVerify());
    body.querySelector('[data-recwiz-phrase="hide"]')
      .addEventListener("click", () => {
        body.hidden = true; card.classList.remove("open"); body.innerHTML = "";
      });
  }

  function _recwizPhrasePrint(words) {
    const w = window.open("", "_blank", "noopener,noreferrer");
    if (!w) {
      toast("Pop-up blocked. Allow pop-ups to print the phrase.", "warn", 5000);
      return;
    }
    const generated = new Date().toISOString().slice(0, 19).replace("T", " ");
    const items = words.map((x) => `<li>${escapeText(x)}</li>`).join("");
    const html = `<!doctype html>
<html><head><meta charset="utf-8"><title>One Link recovery phrase</title>
<style>
  body { font-family: sans-serif; padding: 40px; color: #000; background: #fff; }
  h1 { font-size: 18px; margin-bottom: 4px; }
  .stamp { color: #555; font-size: 12px; margin-bottom: 24px; }
  ol { font-family: monospace; font-size: 18px; columns: 2; column-gap: 40px; }
  ol li { margin: 4px 0; padding-right: 12px; break-inside: avoid; }
  .warn { color: #b80000; font-weight: bold; margin: 24px 0; font-size: 13px; line-height: 1.5; }
</style></head>
<body>
  <h1>One Link recovery phrase</h1>
  <p class="stamp">Generated ${escapeText(generated)}</p>
  <ol>${items}</ol>
  <p class="warn">
    Anyone with these 24 words can be you on a fresh install.
    Store this paper somewhere only you can reach. Do not photograph it.
    Do not store the digital version. One Link cannot recover this phrase.
  </p>
</body></html>`;
    w.document.open();
    w.document.write(html);
    w.document.close();
    w.focus();
    setTimeout(() => { try { w.print(); } catch (e) { /* user can ctrl+p */ } }, 300);
  }

  function _recwizPhraseStartVerify() {
    const card = document.getElementById("recwiz-track-phrase");
    const body = card.querySelector(".recwiz-card-body");
    const positions = [];
    while (positions.length < 3) {
      const p = 1 + Math.floor(Math.random() * 24);
      if (!positions.includes(p)) positions.push(p);
    }
    positions.sort((a, b) => a - b);
    const rows = positions.map((p) => `
      <div class="recwiz-verify-row">
        <label for="recwiz-verify-${p}">Word ${p}</label>
        <input type="text" id="recwiz-verify-${p}" class="recwiz-verify-input"
               data-recwiz-pos="${p}" autocomplete="off" spellcheck="false" />
      </div>`).join("");
    body.innerHTML = `
      <p class="recwiz-card-desc">
        Type these three words from your paper to confirm you wrote
        them correctly. Position 1 is the first word.
      </p>
      ${rows}
      <p class="recwiz-feedback" id="recwiz-phrase-fb"></p>
      <div class="recwiz-card-actions">
        <button type="button" class="recwiz-btn" data-recwiz-phrase="cancel-verify">Back to phrase</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" data-recwiz-phrase="submit-verify" disabled>
          Confirm recovery
        </button>
      </div>
    `;
    const inputs = Array.from(body.querySelectorAll(".recwiz-verify-input"));
    const submit = body.querySelector('[data-recwiz-phrase="submit-verify"]');
    function check() {
      submit.disabled = inputs.some((i) => !i.value.trim());
      inputs.forEach((i) => i.classList.remove("bad"));
    }
    inputs.forEach((i) => i.addEventListener("input", check));
    inputs[0].focus();
    body.querySelector('[data-recwiz-phrase="cancel-verify"]')
      .addEventListener("click", () => _recwizPhraseShow());
    submit.addEventListener("click", async () => {
      const submitted = inputs.map((i) => ({
        pos: Number(i.dataset.recwizPos),
        word: i.value.trim().toLowerCase(),
      })).sort((a, b) => a.pos - b.pos);
      submit.disabled = true;
      const fb = body.querySelector("#recwiz-phrase-fb");
      fb.className = "recwiz-feedback";
      fb.textContent = "Checking...";
      try {
        const res = await api.recoveryPhraseVerify(
          submitted.map((x) => x.pos),
          submitted.map((x) => x.word),
        );
        if (res.ok) {
          fb.className = "recwiz-feedback good";
          fb.textContent = "Verified. Your recovery phrase is set up.";
          toast("Recovery phrase verified.", "good", 4000);
          await _recwizRefreshStatus();
          await refreshOneSetup();
        } else {
          const mismatches = (res.mismatches || []).map(Number);
          inputs.forEach((i) => {
            const pos = Number(i.dataset.recwizPos);
            i.classList.toggle("bad", mismatches.includes(pos));
          });
          fb.className = "recwiz-feedback bad";
          fb.textContent = `Words ${mismatches.join(", ")} did not match. Re-check your paper.`;
          submit.disabled = false;
        }
      } catch (e) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = `Verify failed: ${errorToastBody(e)}`;
        submit.disabled = false;
      }
    });
  }

