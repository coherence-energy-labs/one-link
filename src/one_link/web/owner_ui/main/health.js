  function oneHealthExplainers() {
    return {
      protection: {
        title: "Protection",
        plain: "How well your identity, encryption, trust checks, privacy proof, and lost-device controls are protecting you.",
        next: "Add trusted devices, verify people in person, and review privacy proof.",
        action: "view_privacy_proof",
        cta: "Review privacy proof"
      },
      speed: {
        title: "Speed",
        plain: "Whether One Link can find a nearby, trusted, fast path without making you choose the route yourself.",
        next: "Keep trusted devices awake and let One Link use the best local path automatically.",
        action: "review_speed",
        cta: "Check fastest path"
      },
      recovery: {
        title: "Recovery",
        plain: "How ready you are if a phone or computer is lost, replaced, offline, or stolen.",
        next: "Set recovery and keep at least one second trusted device enrolled.",
        action: "set_recovery",
        cta: "Set recovery"
      },
      devices: {
        title: "Devices",
        plain: "How many of your own devices are enrolled, trusted, reachable, and safe to use as One.",
        next: "Add your phone or laptop so One Link can route and recover for you.",
        action: "add_device",
        cta: "Add a device"
      },
      people: {
        title: "People",
        plain: "How clearly One Link knows who you trust for chats, files, calls, verification, and safety.",
        next: "Pair trusted people and verify important contacts in person.",
        action: "pair_person",
        cta: "Find trusted people"
      }
    };
  }
  function normalizeOneHealthId(value) {
    return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  }
  function oneHealthScoreById(id) {
    const key = normalizeOneHealthId(id);
    return (state.oneHealth?.scores || []).find(s => normalizeOneHealthId(s.id || s.label) === key) || null;
  }
  function bestOneHealthActionId() {
    const health = state.oneHealth || {};
    const first = (health.actions || []).find(a => a && a.id);
    if (first?.id) return first.id;
    const scores = (health.scores || []).filter(s => s && s.score != null);
    const lowest = scores.sort((a, b) => Number(a.score || 0) - Number(b.score || 0))[0];
    const explainers = oneHealthExplainers();
    const mapped = explainers[normalizeOneHealthId(lowest?.id || lowest?.label)]?.action;
    return mapped || "finish_setup";
  }
  function oneHealthGuideFocus() {
    const explainers = oneHealthExplainers();
    const selected = normalizeOneHealthId(state.oneHealthGuideSelected || "");
    if (explainers[selected]) return selected;
    const best = bestOneHealthActionId();
    const match = Object.entries(explainers).find(([, exp]) => exp.action === best);
    return match?.[0] || "protection";
  }
  function setOneHealthGuideFocus(id) {
    const key = normalizeOneHealthId(id);
    if (!oneHealthExplainers()[key]) return;
    state.oneHealthGuideSelected = key;
    renderOneHealthGuide();
    $("#one-health-guide-autopilot")?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
  function renderOneHealthGuide() {
    const health = state.oneHealth || {};
    const explainers = oneHealthExplainers();
    const focus = oneHealthGuideFocus();
    const guideScore = $("#one-health-guide-score");
    const guideHeadline = $("#one-health-guide-headline");
    const guideDetail = $("#one-health-guide-detail");
    if (guideScore) guideScore.textContent = health.score != null ? String(health.score) : "--";
    if (guideHeadline) guideHeadline.textContent = health.headline || "Checking One Link";
    if (guideDetail) {
      guideDetail.textContent = health.detail
        || "One Setup introduces this during first run, and you can reopen it here any time.";
    }
    const grid = $("#one-health-guide-grid");
    if (grid) {
      grid.replaceChildren();
      for (const id of ["protection", "speed", "recovery", "devices", "people"]) {
        const exp = explainers[id];
        const score = oneHealthScoreById(id);
        const card = el("div", "one-health-guide-card");
        card.setAttribute("role", "button");
        card.setAttribute("tabindex", "0");
        card.setAttribute("aria-label", `Show ${exp.title} next step`);
        card.setAttribute("aria-pressed", id === focus ? "true" : "false");
        card.dataset.oneHealthAction = exp.action;
        card.dataset.oneHealthFocus = id;
        card.classList.toggle("is-selected", id === focus);
        const top = el("div", "one-health-guide-card-top");
        top.appendChild(el("b", "", exp.title));
        top.appendChild(el("strong", "", score?.score != null ? String(score.score) : "--"));
        card.appendChild(top);
        card.appendChild(el("p", "", exp.plain));
        card.appendChild(el("span", "", score?.detail || exp.next));
        card.appendChild(el("span", "one-health-guide-cta", exp.cta));
        grid.appendChild(card);
      }
    }
    const focused = explainers[focus] || explainers.protection;
    const bestAction = focused.action || bestOneHealthActionId();
    const best = (health.actions || []).find(a => a.id === bestAction) || {};
    const autopilot = $("#one-health-guide-autopilot");
    const autoTitle = $("#one-health-guide-autopilot-title");
    const autoDetail = $("#one-health-guide-autopilot-detail");
    const autoButton = $("#one-health-guide-autopilot-button");
    if (autopilot) autopilot.classList.toggle("is-selected", !!state.oneHealthGuideSelected);
    if (autoTitle) autoTitle.textContent = best.label || focused.cta || "Let One Link handle the next step";
    if (autoDetail) {
      autoDetail.textContent = best.detail
        || `${focused.title}: ${focused.next} Click the button only when you want One Link to open the right place.`;
    }
    if (autoButton) {
      autoButton.dataset.oneHealthAction = bestAction;
      autoButton.textContent = bestAction === "finish_setup" ? "Resume setup" : (focused.cta || "Do next step");
    }
    const actions = $("#one-health-guide-actions");
    if (actions) {
      actions.replaceChildren();
      const healthActions = (health.actions || []).slice(0, 5);
      const rows = healthActions.length ? healthActions : [{
        id: "finish_setup",
        label: "Walk through One Setup",
        detail: "Review your identity, devices, recovery, privacy proof, and first private send."
      }];
      for (const a of rows) {
        const row = el("div", "one-health-guide-action");
        const text = el("div", "");
        text.appendChild(el("b", "", a.label || "Recommended action"));
        text.appendChild(el("span", "", a.detail || "One Link will open the right place."));
        row.appendChild(text);
        const btn = el("button", "", a.id === "finish_setup" ? "Resume setup" : "Open");
        btn.dataset.oneHealthAction = a.id || "finish_setup";
        row.appendChild(btn);
        actions.appendChild(row);
      }
    }
  }
  function openOneHealthGuide() {
    state.oneHealthGuideReturnPending = false;
    renderOneHealthGuide();
    const backdrop = $("#one-health-guide-backdrop");
    if (!backdrop) return;
    backdrop.classList.add("show");
    backdrop.setAttribute("aria-hidden", "false");
    $("#one-health-guide-close")?.focus();
  }
  function closeOneHealthGuide() {
    const backdrop = $("#one-health-guide-backdrop");
    if (!backdrop) return;
    backdrop.classList.remove("show");
    backdrop.setAttribute("aria-hidden", "true");
    $("#one-health")?.focus();
  }
  async function openOneHealthGuideDestination(action) {
    state.oneHealthGuideReturnPending = true;
    closeOneHealthGuide();
    await Promise.resolve(runOneHealthAction(action || bestOneHealthActionId()));
    setTimeout(() => {
      const waitingOnOverlay = document.querySelector(
        "#privacy-panel-overlay.show, #settings-backdrop.show, #onboarding-backdrop[style*='flex'], #discover-overlay.show"
      );
      if (!waitingOnOverlay) returnToOneHealthGuideIfPending();
    }, 120);
  }
  function returnToOneHealthGuideIfPending() {
    if (!state.oneHealthGuideReturnPending) return false;
    state.oneHealthGuideReturnPending = false;
    setTimeout(() => openOneHealthGuide(), 90);
    return true;
  }
  function renderOneHealth() {
    const health = state.oneHealth || {};
    const healthCard = $("#one-health");
    if (healthCard) {
      healthCard.setAttribute("role", "button");
      healthCard.setAttribute("tabindex", "0");
      healthCard.setAttribute("aria-label", "Open One Health guide");
      healthCard.title = "Open One Health guide";
    }
    const score = $("#one-health-score");
    const title = $("#one-health-title");
    const detail = $("#one-health-detail");
    if (score) score.textContent = health.score != null ? String(health.score) : "--";
    if (title) title.textContent = health.headline || "Checking One Link";
    if (detail) detail.textContent = health.detail || "Protection, speed, recovery, people, and devices.";
    const grid = $("#one-health-grid");
    if (grid) {
      grid.replaceChildren();
      for (const s of (health.scores || []).slice(0, 5)) {
        const card = el("div", "one-health-metric");
        card.title = "Open One Health guide";
        card.appendChild(el("b", "", `${s.score ?? "--"}`));
        card.appendChild(el("span", "", s.label || s.id || "score"));
        // v0.21.x: recovery score row carries per-track readiness
        // so the card can show 'phrase + bundle (2 of 3)' instead
        // of just the raw score. Encourages users to add another
        // recovery path for defense in depth.
        if (s.id === "recovery" && s.tracks_ready) {
          const tr = s.tracks_ready;
          const parts = [];
          if (tr.phrase) parts.push("phrase");
          if (tr.bundle) parts.push("bundle");
          if (tr.social) parts.push("shares");
          const ready = Number(s.tracks_ready_count || 0);
          const detail = parts.length
            ? `${parts.join(" + ")} (${ready} of 3)`
            : "no tracks yet";
          const tracks = el("span", "one-health-tracks", detail);
          tracks.style.fontSize = "10px";
          tracks.style.color = "var(--text-dim)";
          tracks.style.marginTop = "2px";
          card.appendChild(tracks);
          card.title = `Open recovery wizard — ${detail}`;
        }
        grid.appendChild(card);
      }
    }
    const actions = $("#one-health-actions");
    if (actions) {
      actions.replaceChildren();
      for (const a of (health.actions || []).slice(0, 4)) {
        const row = el("div", "one-health-row");
        const text = el("div", "");
        text.appendChild(el("b", "", a.label || "Recommended action"));
        text.appendChild(el("span", "", a.detail || ""));
        row.appendChild(text);
        const btn = el("button", a.severity === "urgent" ? "danger" : a.severity === "recommended" ? "warn" : "", "Open");
        btn.dataset.oneHealthAction = a.id || "";
        btn.title = a.detail || a.label || "Open";
        row.appendChild(btn);
        actions.appendChild(row);
      }
      if (!actions.children.length) {
        const row = el("div", "one-health-row");
        row.appendChild(el("b", "", "Everything important is ready"));
        row.appendChild(el("span", "tag", "ok"));
        actions.appendChild(row);
      }
    }
    const people = $("#one-health-people");
    if (people) {
      people.replaceChildren();
      const lost = health.lost_device || {};
      const calls = health.calls || {};
      const summary = el("div", "one-health-row");
      const summaryText = el("div", "");
      summaryText.appendChild(el("b", "", "Lost-device and calls"));
      summaryText.appendChild(el("span", "", `${lost.human || "Checking your devices…"} ${calls.human || ""}`));
      summary.appendChild(summaryText);
      summary.appendChild(el("span", "tag", `${lost.unsafe_devices || 0} unsafe`));
      people.appendChild(summary);
      for (const p of (health.people || []).slice(0, 6)) {
        const row = el("div", "one-health-row");
        const text = el("div", "");
        text.appendChild(el("b", "", p.label || "Trusted"));
        text.appendChild(el("span", "", p.kind === "device" ? `Safety: ${p.safety_state || "trusted"}` : (p.verified ? "Verified in person" : "Trusted person")));
        row.appendChild(text);
        row.appendChild(el("span", "tag", p.kind || "one"));
        people.appendChild(row);
      }
    }
    const timeline = $("#one-health-timeline");
    if (timeline) {
      timeline.replaceChildren();
      for (const t of (health.timeline || []).slice(0, 6)) {
        const row = el("div", "one-health-row");
        const text = el("div", "");
        text.appendChild(el("b", "", String(t.event || "trust event").replaceAll("_", " ")));
        text.appendChild(el("span", "", t.detail || "Recorded by One Link"));
        row.appendChild(text);
        row.appendChild(el("span", "tag", t.severity || "info"));
        timeline.appendChild(row);
      }
    }
    renderOneHealthGuide();
  }
  async function refreshOneHealth() {
    try {
      state.oneHealth = await api.oneHealth();
      renderOneHealth();
    } catch (_e) {
      renderOneHealth();
    }
  }
  async function runOneHealthAction(id) {
    if (id === "finish_setup") return openOneSetupFromState();
    if (id === "add_device") {
      await refreshOneSetup();
      showOnboardingStep(4);
      $("#onboarding-backdrop").style.display = "flex";
      return oneSetupAddDevice();
    }
    if (id === "set_recovery") return oneSetupMarkRecoveryConfigured();
    if (id === "review_speed") {
      closeOneHealthGuide();
      const details = $("#activity-advanced-tools");
      if (details) details.open = true;
      const target = $("#fabric-truth") || $("#no-router-kit") || $("#activity-advanced-tools");
      target?.scrollIntoView({ block: "nearest", behavior: "smooth" });
      return toast("One Link is checking the fastest trusted path.", "info", 3000);
    }
    if (id === "review_lost_device") {
      $("#self-mesh-safety-actions").open = true;
      return $("#self-mesh-kit")?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
    if (id === "pair_person") return $("#btn-discover")?.click();
    if (id === "view_privacy_proof") {
      await api.setupAction("privacy_proof_viewed").catch(() => {});
      if (typeof window.openPrivacyPanel === "function") await window.openPrivacyPanel();
      await refreshOneSetup();
      return;
    }
    return toast("That check is already handled.", "info", 2500);
  }
