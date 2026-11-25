  // Update instructions always bind to the exact tagged GitHub release that
  // produced the notification. A floating package-manager command could
  // resolve a different artifact and bypass the release's verification
  // contract, so this surface never offers one.
  //
  // The chip+banner+modal share a single source of truth: the
  // latest CheckResult cached at ``state._updateInfo``. The modal's
  // CTAs read from there; dismissal of either banner or chip writes
  // the same localStorage key so the surfaces stay consistent.
  // The rolling channel's tag is `auto-latest` forever, so a version-keyed
  // dismissal would hide EVERY future rolling update after one click. Key
  // rolling dismissals by the published build commit instead — a new build
  // means a new commit means the banner honestly returns.
  function _updateDismissKey(info) {
    const id = info.channel === "rolling" && info.latest_commit
      ? info.latest_commit
      : info.latest_version;
    return `ol_update_dismissed:${id}`;
  }
  function _shortCommit(commit) {
    return typeof commit === "string" ? commit.slice(0, 9) : "";
  }
  async function checkForUpdate() {
    const banner = $("#update-banner");
    const chip   = $("#header-update-chip");
    let info;
    try {
      info = await api.get("/api/update/check");
    } catch (_e) {
      return;  // network/auth fail - silently no-op
    }
    state._updateInfo = info || null;
    // Treat any non-"newer" result as "nothing to do" — hide both
    // surfaces, return.
    if (!info || info.status !== "newer") {
      banner?.classList.remove("show");
      chip?.classList.remove("show");
      return;
    }
    const dismissKey = _updateDismissKey(info);
    if (localStorage.getItem(dismissKey) === "1") {
      banner?.classList.remove("show");
      chip?.classList.remove("show");
      return;
    }
    // ── Top banner copy (kept for users who want the full text) ──
    const txt = $("#update-banner-text");
    const link = $("#update-banner-link");
    if (txt) {
      // Honest, install-method-agnostic copy. A rolling build's version
      // string never changes ("auto-latest" vs "0.21.0-alpha" says
      // nothing), so its identity is the build commit.
      if (info.channel === "rolling") {
        const latest = _shortCommit(info.latest_commit);
        const local = _shortCommit(info.local_commit);
        txt.textContent = local
          ? ` A newer build (${latest}) is published; you're running ${local}.`
          : ` A newer build (${latest}) is published.`;
      } else {
        txt.textContent =
          ` Latest is ${info.latest_version}; you're on v${info.local_version}.`;
      }
    }
    if (link && info.latest_url) {
      link.href = info.latest_url;
    }
    // The executable handoff is dynamic capability truth, not an environment
    // opt-in. /api/me exposes it only after hashing the complete managed
    // bundle and the separately frozen updater helper — AND the server must
    // say this exact newer build carries install authority
    // (can_self_install): rolling builds never do, so offering the button
    // for one would promise an install that must fail closed.
    const installBtn = $("#update-banner-install");
    if (installBtn) {
      const canInstall = state.me?.update_install_available === true
        && info.can_self_install === true;
      installBtn.style.display = canInstall ? "" : "none";
      installBtn.textContent = "Install update";
    }
    banner?.classList.add("show");
    // ── Header chip ──
    if (chip) {
      chip.classList.add("show");
      const labelEl = chip.querySelector(".hu-label");
      if (labelEl) labelEl.textContent = "Update";
      chip.setAttribute(
        "title",
        info.channel === "rolling"
          ? `Update to build ${_shortCommit(info.latest_commit)} — click for release notes`
          : `Update to ${info.latest_version} (you're on v${info.local_version}) — click for release notes`,
      );
    }
  }
  // Human-readable artifact size. The plan reports bytes; "121 MB" is what a
  // person deciding whether to start a download on a phone tether needs.
  function _formatBytes(n) {
    if (typeof n !== "number" || !isFinite(n) || n < 0) return "";
    if (n < 1024) return n + " B";
    const units = ["KB", "MB", "GB"];
    let v = n / 1024, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (v < 10 ? v.toFixed(1) : Math.round(v)) + " " + units[i];
  }

  // Resolve /api/update/plan and describe the download in the modal.
  //
  // This endpoint was registered, guarded and correct, and NOTHING called it —
  // found by auditing which registered routes have no consumer. It sits on the
  // update path, so a regression in it would have been invisible.
  //
  // Every failure mode here leaves the modal exactly as it was. The plan is a
  // convenience; the install does not depend on it, and a user must never be
  // blocked from updating because a description could not be fetched.
  async function _fillUpdatePlan() {
    const host = $("#um-plan");
    if (!host) return;
    let plan;
    try {
      plan = await api.get("/api/update/plan");
    } catch (_e) {
      return;  // offline, policy-disabled, or unavailable — say nothing
    }
    if (!plan || !plan.artifact || plan.status === "error") return;
    const size = _formatBytes(plan.artifact.size);
    host.innerHTML = "";

    const line = document.createElement("div");
    line.className = "um-plan-line";
    const name = document.createElement("code");
    name.textContent = plan.artifact.filename || "release artifact";
    line.append("Downloads ", name);
    if (size) line.append(" · " + size);
    host.appendChild(line);

    if (plan.tag) {
      const pin = document.createElement("div");
      pin.className = "um-plan-note";
      // Deliberately describes the mechanism rather than promising safety.
      // The verification that matters happens in the external helper, and
      // this text is not evidence of it.
      pin.append("Pinned to release ");
      const tag = document.createElement("code");
      tag.textContent = plan.tag;
      pin.appendChild(tag);
      pin.append(". Signatures are checked by the updater before anything "
                 + "is activated, and the update rolls back if the new "
                 + "version does not come up healthy.");
      host.appendChild(pin);
    }
    host.hidden = false;
  }

  function openUpdateModal() {
    const info = state._updateInfo;
    const backdrop = $("#update-modal-backdrop");
    if (!backdrop || !info) return;
    // Clear any plan from a previous open before re-resolving, so a stale
    // artifact size can never be shown against a newer release.
    const planHost = $("#um-plan");
    if (planHost) { planHost.hidden = true; planHost.innerHTML = ""; }
    // Versions. Rolling builds all call themselves the same version, so
    // the honest identity to diff is the build commit.
    const cur = $("#um-current-version");
    const nxt = $("#um-latest-version");
    if (info.channel === "rolling") {
      if (cur) {
        cur.textContent = _shortCommit(info.local_commit)
          || "v" + (info.local_version || "?");
      }
      if (nxt) nxt.textContent = _shortCommit(info.latest_commit) || "latest";
    } else {
      if (cur) cur.textContent = "v" + (info.local_version || "?");
      if (nxt) nxt.textContent = info.latest_version || "latest";
    }
    // Release-notes body — re-uses the renderMarkdownDoc renderer
    // built for chat. info.latest.body is the GitHub Release's
    // markdown notes; some releases have none, so we degrade
    // gracefully to "No release notes were provided."
    const notesHost = $("#um-notes");
    if (notesHost) {
      notesHost.innerHTML = "";
      const body = (info.latest && info.latest.body) || "";
      if (body.trim()) {
        try {
          const md = renderMarkdownDoc(body);
          notesHost.appendChild(md);
        } catch (_e) {
          const pre = document.createElement("pre");
          pre.textContent = body;
          notesHost.appendChild(pre);
        }
      } else {
        const e = document.createElement("div");
        e.className = "um-notes-error";
        e.textContent = "No release notes were provided for this release.";
        notesHost.appendChild(e);
      }
    }
    // Exact release CTA and verification instructions for every install type.
    const dl = $("#update-modal-download");
    const releaseLink = $("#update-modal-release-link");
    const howto = $("#um-howto");
    if (releaseLink && info.latest_url) {
      releaseLink.href = info.latest_url;
    }
    if (dl) {
      const rolling = info.channel === "rolling";
      const canInstall = state.me?.update_install_available === true
        && info.can_self_install === true;
      dl.href = canInstall
        ? "#install-authenticated-update"
        : rolling
          ? (info.action_url || "https://weareone-link.org/download/")
          : (info.latest_url || "https://github.com/coherence-energy-labs/one-link/releases");
      dl.style.display = "";
      if (canInstall) {
        dl.removeAttribute("target");
        dl.removeAttribute("rel");
      } else {
        dl.setAttribute("target", "_blank");
        dl.setAttribute("rel", "noopener noreferrer");
      }
      const label = dl.querySelector(".um-download-label");
      if (label) {
        label.textContent = canInstall
          ? "Install verified update"
          : rolling
            ? "Download latest build"
            : "Inspect exact release";
      }
      // Tell the user what "Install verified update" will actually fetch,
      // before they click it. Fire-and-forget: the modal is already usable,
      // and a plan that cannot be resolved must never block the install.
      if (canInstall) _fillUpdatePlan();
    }
    if (howto) {
      const canInstall = state.me?.update_install_available === true
        && info.can_self_install === true;
      if (canInstall) {
        howto.textContent =
          'One Link will hand this exact release to a separate authenticated '
          + 'updater. It independently verifies the tagged release workflow, '
          + 'Sigstore bundles, SHA-256 evidence, SBOM, complete application '
          + 'tree, rollback order, and post-restart daemon/UI health. The old '
          + 'bundle stays recoverable unless every check passes.';
      } else if (info.channel === "rolling") {
        howto.textContent =
          'This update comes from the rolling channel, which is refreshed by '
          + 'downloading and reinstalling: only tagged, Sigstore-signed '
          + 'releases carry in-app install authority. Download the latest '
          + 'build and install it over this one — your data lives outside '
          + 'the application folder and stays in place.';
      } else {
        howto.textContent =
          'This runtime is not a validated standalone bundle, so in-app '
          + 'replacement is unavailable. Inspect the exact tagged release and '
          + 'use only its matching architecture-labelled artifact after its '
          + 'SHA256SUMS and Sigstore evidence verify.';
      }
    }
    backdrop.classList.add("show");
    // Focus the close button so Esc-to-close works without a click.
    setTimeout(() => $("#update-modal-cancel")?.focus(), 30);
  }
  function closeUpdateModal() {
    $("#update-modal-backdrop")?.classList.remove("show");
  }
  function _dismissUpdateForCurrentVersion() {
    const info = state._updateInfo;
    if (info && info.latest_version) {
      try {
        localStorage.setItem(_updateDismissKey(info), "1");
      } catch (_e) {}
    }
    $("#update-banner")?.classList.remove("show");
    $("#header-update-chip")?.classList.remove("show");
  }

  async function installAuthenticatedUpdate() {
    if (
      state.me?.update_install_available !== true
      || state._updateInfo?.can_self_install !== true
    ) {
      openUpdateModal();
      return;
    }
    if (state._updateInstallInFlight) return;
    state._updateInstallInFlight = true;
    const bannerButton = document.getElementById("update-banner-install");
    const modalButton = document.getElementById("update-modal-download");
    const modalLabel = modalButton?.querySelector(".um-download-label");
    if (bannerButton) {
      bannerButton.disabled = true;
      bannerButton.textContent = "Preparing…";
    }
    if (modalButton) {
      modalButton.setAttribute("aria-disabled", "true");
      modalButton.style.pointerEvents = "none";
    }
    if (modalLabel) modalLabel.textContent = "Preparing verified update…";
    toast(
      "Preparing the authenticated updater. Active calls or transfers must finish first.",
      "info",
      7000,
    );
    let accepted = false;
    try {
      const result = await api.updateInstall();
      accepted = result?.status === "handoff_started" && result?.ok === true;
      if (!accepted) throw new Error("The updater did not accept the handoff.");
      if (bannerButton) bannerButton.textContent = "Restarting…";
      if (modalLabel) modalLabel.textContent = "Restarting One Link…";
      toast(
        "Update accepted. The helper will verify the release, then start the new build or restore the prior build if any check fails.",
        "good",
        10000,
      );
      closeUpdateModal();
    } catch (error) {
      toast(`Update did not start: ${errorToastBody(error)}`, "bad", 10000);
    } finally {
      if (!accepted) {
        state._updateInstallInFlight = false;
        if (bannerButton) {
          bannerButton.disabled = false;
          bannerButton.textContent = "Install update";
        }
        if (modalButton) {
          modalButton.removeAttribute("aria-disabled");
          modalButton.style.pointerEvents = "";
        }
        if (modalLabel) modalLabel.textContent = "Install verified update";
      }
    }
  }

  // May 16 2026 - RED-TEAM FIX. This script block runs at end-of-
  // body, by which point DOMContentLoaded has ALREADY fired.
  // Registering a listener for it after the fact never fires -
  // these handlers were silently dead. Replace with an
  // "either run now or wait for DOMContentLoaded" helper.
  function _onReady(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      // DOM already ready; run synchronously. setTimeout(0) defers
      // to the next tick so any same-block code that constructs
      // referenced elements still has a chance to run first.
      setTimeout(fn, 0);
    }
  }

  // The banner first opens the confirmation/details surface. Only the modal's
  // explicit CTA emits confirmed_install=true.
  _onReady(() => {
    const installBtn = document.getElementById("update-banner-install");
    if (!installBtn) return;
    installBtn.addEventListener("click", () => {
      openUpdateModal();
    });
  });

  // Per-version dismiss; clicked once, hidden until a newer version
  // is published. The dismiss button on the banner and the close
  // button on the modal both route through _dismissUpdateForCurrentVersion
  // so the chip + banner stay consistent.
  _onReady(() => {
    const dismiss = document.getElementById("update-banner-dismiss");
    if (dismiss) {
      dismiss.addEventListener("click", _dismissUpdateForCurrentVersion);
    }
    // 2026-06-04: chip → opens the polished update modal. Clicking
    // the chip is the most visible affordance; the modal does the
    // heavy lifting of explaining what's available + offering the
    // right CTA. Defer the listener attach via _onReady so the
    // chip element exists when we wire to it.
    const chip = document.getElementById("header-update-chip");
    if (chip) {
      chip.addEventListener("click", () => {
        if (state._updateInfo && state._updateInfo.status === "newer") {
          openUpdateModal();
        }
      });
    }
    // Modal interactions — cancel button, backdrop click, Esc key.
    const backdrop = document.getElementById("update-modal-backdrop");
    const cancel   = document.getElementById("update-modal-cancel");
    const install = document.getElementById("update-modal-download");
    cancel?.addEventListener("click", closeUpdateModal);
    install?.addEventListener("click", (ev) => {
      // Hijack the anchor into the in-app install ONLY when this exact
      // newer build carries install authority; otherwise the anchor is a
      // plain download/inspect link and must stay one.
      if (state.me?.update_install_available !== true) return;
      if (state._updateInfo?.can_self_install !== true) return;
      ev.preventDefault();
      installAuthenticatedUpdate();
    });
    backdrop?.addEventListener("click", (ev) => {
      // Click on the backdrop itself (not the modal panel) closes.
      if (ev.target === backdrop) closeUpdateModal();
    });
    // Esc-to-close (only when the modal is the topmost overlay so
    // we don't steal Esc from a dialog stacked above us). Use
    // capture phase so we run before any global handler eats it.
    document.addEventListener("keydown", (ev) => {
      if (ev.key !== "Escape") return;
      if (!backdrop || !backdrop.classList.contains("show")) return;
      ev.preventDefault();
      closeUpdateModal();
    });
    // Banner "View release" link click also opens the modal — the
    // modal is the better UX (release notes + download CTA),
    // so we intercept the GitHub-redirect-only path. Ctrl/Cmd+
    // click still opens in a new tab via the anchor's default
    // behavior for power users.
    const bannerLink = document.getElementById("update-banner-link");
    bannerLink?.addEventListener("click", (ev) => {
      if (ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.button === 1) return;
      ev.preventDefault();
      openUpdateModal();
    });
  });

  // v0.21.x rotation-in-progress banner. Polls /api/v1/recovery/rotate/status
  // on load + on every rotation WS event (peer_rotated /
  // rotation_announcement_acked, wired in the WS dispatcher) and
  // shows the banner whenever summary.pending > 0. Dismiss hides
  // for the session (sessionStorage so a daemon restart re-shows;
  // the rotation isn't actually complete until peers ack).
  async function refreshRotationBanner() {
    const banner = document.getElementById("rotation-banner");
    if (!banner) return;
    if (sessionStorage.getItem("ol_rotation_banner_dismissed") === "1") {
      banner.classList.remove("show");
      return;
    }
    let status;
    try { status = await api.recoveryRotateStatus(); }
    catch { banner.classList.remove("show"); return; }
    const sum = (status && status.summary) || { total: 0, pending: 0, acked: 0 };
    if (!sum.pending) {
      // No pending: hide. If the row was previously dismissed and
      // a new rotation happens, clear the session flag so the new
      // pending state re-shows.
      banner.classList.remove("show");
      sessionStorage.removeItem("ol_rotation_banner_dismissed");
      return;
    }
    const text = document.getElementById("rotation-banner-text");
    if (text) {
      text.textContent =
        `${sum.acked} of ${sum.total} peers acknowledged. ` +
        `The remaining ${sum.pending} will pick up the new key the next time this device contacts them.`;
    }
    banner.classList.add("show");
  }
  _onReady(() => {
    const dismiss = document.getElementById("rotation-banner-dismiss");
    const open = document.getElementById("rotation-banner-open");
    if (dismiss) {
      dismiss.addEventListener("click", () => {
        sessionStorage.setItem("ol_rotation_banner_dismissed", "1");
        document.getElementById("rotation-banner")?.classList.remove("show");
      });
    }
    if (open) {
      open.addEventListener("click", () => {
        document.getElementById("rotation-banner")?.classList.remove("show");
        // Open the wizard; the rotation card lives inside it.
        // _showRecoveryWizard exists in the recovery-wizard module.
        if (typeof _showRecoveryWizard === "function") {
          _showRecoveryWizard().catch(() => {});
        }
      });
    }
    // Initial check on page load.
    refreshRotationBanner().catch(() => {});
    // v0.21.x first-launch install-warning explainer. Show once
    // per browser/device, dismissable. The banner reframes the
    // SmartScreen / Gatekeeper warning as a trust-building beat
    // (no corporation can revoke our right to ship). Pin: only
    // fires when the user has NEVER seen it on this device, and
    // never fires alongside the rotation banner (rotation is
    // urgent + competing UX would confuse).
    try {
      const SEEN_KEY = "one_link.install_warning_seen";
      const seen = (function () {
        try { return localStorage.getItem(SEEN_KEY) === "1"; }
        catch (_) { return true; /* no localStorage = silent skip */ }
      })();
      const iwb = document.getElementById("install-warning-banner");
      const iwbDismiss = document.getElementById("install-warning-banner-dismiss");
      const iwbMore = document.getElementById("install-warning-banner-more");
      const iwbModal = document.getElementById("install-warning-modal-backdrop");
      const iwbModalClose = document.getElementById("install-warning-modal-close");
      if (iwb && !seen) {
        iwb.classList.add("show");
      }
      function _hideIwb() {
        try { localStorage.setItem(SEEN_KEY, "1"); } catch (_) {}
        iwb?.classList.remove("show");
      }
      iwbDismiss?.addEventListener("click", _hideIwb);
      iwbMore?.addEventListener("click", () => {
        iwbModal?.classList.add("show");
      });
      iwbModalClose?.addEventListener("click", () => {
        iwbModal?.classList.remove("show");
        _hideIwb();
      });
      iwbModal?.addEventListener("click", (ev) => {
        // Click outside the inner card closes.
        if (ev.target === iwbModal) {
          iwbModal.classList.remove("show");
        }
      });
      // Escape closes the modal too.
      document.addEventListener("keydown", (ev) => {
        if (ev.key === "Escape" && iwbModal?.classList.contains("show")) {
          iwbModal.classList.remove("show");
        }
      });
    } catch (_) { /* defensive */ }
  });
