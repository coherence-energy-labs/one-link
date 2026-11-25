  // ── recovery wizard: BACKUP track ───────────────────────────────
  function _recwizRenderBackupCard(s) {
    const card = document.getElementById("recwiz-track-backup");
    if (!card) return;
    const ready = !!s.ready;
    const avail = !!s.available;
    const status = ready ? "Exported" : avail ? "Not exported" : "Unavailable";
    const cls = ready ? "ready" : avail ? "partial" : "unavailable";
    const last = ready
      ? `Last export ${_recwizFormatRelative(s.last_action_at_ms)} (${_recwizHumanSize(s.last_export_size_bytes)}).`
      : "";
    card.innerHTML = `
      <div class="recwiz-card-head">
        <div class="recwiz-card-name">Encrypted backup file</div>
        <div class="recwiz-card-status ${cls}">${escapeText(status)}</div>
      </div>
      <p class="recwiz-card-desc">
        A single sealed file (.olbak) with your identity, chat history,
        and settings. Keep it on a USB stick, a second device, or an
        encrypted cloud folder. It is encrypted under your recovery
        phrase: without that phrase, the file is unreadable to anyone,
        including us.
      </p>
      <details class="recwiz-help">
        <summary>How does this work?</summary>
        <p>
          The file is an authenticated-encryption blob. The key to
          decrypt it is derived from your 24-word phrase. Without the
          phrase, the bytes look like random noise. With the phrase,
          a fresh install can restore everything inside the bundle:
          your identity, chat history, groups, settings. Keep the
          file and the phrase in separate places so a single point
          of failure does not lose both.
        </p>
      </details>
      ${last ? `<p class="recwiz-card-meta">${escapeText(last)}</p>` : ""}
      <div class="recwiz-card-actions">
        <button type="button" class="recwiz-btn recwiz-btn-primary" data-recwiz-backup="export">
          ${ready ? "Export new backup" : "Download backup"}
        </button>
        <button type="button" class="recwiz-btn" data-recwiz-backup="test">Test a backup file</button>
        <label style="display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--text-dim);">
          <input type="checkbox" id="recwiz-backup-includefiles" />
          Include received files
        </label>
      </div>
      <div class="recwiz-card-body" hidden></div>
    `;
    card.querySelector('[data-recwiz-backup="export"]')
      .addEventListener("click", () => _recwizBackupExport());
    card.querySelector('[data-recwiz-backup="test"]')
      .addEventListener("click", () => _recwizBackupTestStart());
  }

  // 'Test a backup file' - non-destructive verify that an .olbak +
  // a 24-word phrase pair correctly. AEAD-decrypts the file in
  // memory (server-side) and reports the bundle's created_ms +
  // plaintext file count without writing to disk.
  function _recwizBackupTestStart() {
    const card = document.getElementById("recwiz-track-backup");
    const body = card.querySelector(".recwiz-card-body");
    body.hidden = false;
    card.classList.add("open");
    body.innerHTML = `
      <p class="recwiz-card-desc">
        Pick an .olbak file and paste the 24-word phrase that should
        decrypt it. Nothing is written; the file and phrase never
        leave this device's daemon.
      </p>
      <input type="file" id="recwiz-backup-test-file" accept=".olbak"
             aria-label="Encrypted backup file to test" />
      <p class="recwiz-card-meta" id="recwiz-backup-test-info" style="margin:6px 0;"></p>
      <textarea class="recwiz-phrase-input" id="recwiz-backup-test-phrase"
                aria-label="24 word recovery phrase"
                autocomplete="off" spellcheck="false"
                placeholder="abandon ability about ..."></textarea>
      <p class="recwiz-feedback" id="recwiz-backup-test-fb"></p>
      <div class="recwiz-card-actions">
        <button type="button" class="recwiz-btn" data-recwiz-backup="test-hide">Hide</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" id="recwiz-backup-test-submit" disabled>
          Check backup
        </button>
      </div>
    `;
    const file = body.querySelector("#recwiz-backup-test-file");
    const info = body.querySelector("#recwiz-backup-test-info");
    const ta = body.querySelector("#recwiz-backup-test-phrase");
    const fb = body.querySelector("#recwiz-backup-test-fb");
    const submit = body.querySelector("#recwiz-backup-test-submit");
    function check() {
      const f = file.files && file.files[0];
      const tokens = String(ta.value || "").trim().split(/\s+/).filter(Boolean);
      submit.disabled = !f || tokens.length < 24;
      if (f && tokens.length === 24) {
        fb.className = "recwiz-feedback";
        fb.textContent = "Ready to check.";
      } else if (!f) {
        fb.className = "recwiz-feedback";
        fb.textContent = "Pick an .olbak file.";
      } else {
        fb.className = "recwiz-feedback";
        fb.textContent = `${tokens.length} of 24 words.`;
      }
    }
    file.addEventListener("change", () => {
      const f = file.files && file.files[0];
      info.textContent = f ? `${f.name} (${_recwizHumanSize(f.size)})` : "";
      check();
    });
    ta.addEventListener("input", check);
    body.querySelector('[data-recwiz-backup="test-hide"]')
      .addEventListener("click", () => {
        body.hidden = true; card.classList.remove("open"); body.innerHTML = "";
      });
    submit.addEventListener("click", async () => {
      submit.disabled = true;
      fb.className = "recwiz-feedback";
      const f = file.files[0];
      if (f.size > 256 * 1024 * 1024) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = "Backup exceeds the 256 MiB recovery limit.";
        submit.disabled = false;
        return;
      }
      fb.textContent = "Uploading and decrypting in memory...";
      let res;
      try {
        res = await api.recoveryBundleTest(ta.value.trim(), f);
      } catch (e) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = errorToastBody(e) || "Check failed.";
        submit.disabled = false;
        return;
      }
      if (!res.valid_phrase) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = `Not a valid 24-word phrase: ${res.error || "decode failed"}.`;
        submit.disabled = false;
        return;
      }
      if (!res.valid_bundle) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = `Phrase decodes, but this file does NOT decrypt: ${res.error || "wrong phrase or tampered file"}.`;
        submit.disabled = false;
        return;
      }
      fb.className = "recwiz-feedback good";
      const when = res.bundle_created_ms
        ? _recwizFormatRelative(res.bundle_created_ms) : "an unknown date";
      fb.textContent = `Valid backup from ${when}, contains ${res.file_count || 0} file${res.file_count === 1 ? "" : "s"}. Your file + phrase pair correctly.`;
      submit.disabled = false;
    });
    setTimeout(() => file.focus(), 60);
  }

  async function _recwizBackupExport() {
    const card = document.getElementById("recwiz-track-backup");
    const btn = card.querySelector('[data-recwiz-backup="export"]');
    const includeFiles = !!card.querySelector("#recwiz-backup-includefiles")?.checked;
    btn.disabled = true;
    const origText = btn.textContent;
    btn.textContent = "Preparing...";
    try {
      const r = await fetch(api.recoveryBackupExportUrl(includeFiles), {
        credentials: "include",
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        throw new Error(j.error || `HTTP ${r.status}`);
      }
      const cd = r.headers.get("Content-Disposition") || "";
      const m = cd.match(/filename="([^"]+)"/);
      const filename = m ? m[1] : "one-link-backup.olbak";
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast(`Backup downloaded (${_recwizHumanSize(blob.size)}).`, "good", 4000);
      await _recwizRefreshStatus();
      await refreshOneSetup();
    } catch (e) {
      toast(`Backup failed: ${e.message || e}`, "bad", 6000);
    } finally {
      btn.disabled = false;
      btn.textContent = origText;
    }
  }

