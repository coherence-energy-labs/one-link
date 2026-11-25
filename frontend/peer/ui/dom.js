  "use strict";

  // ── tiny DOM helpers ─────────────────────────────────────────────────
  const $ = (sel) => document.querySelector(sel);
  const text = (el, s) => { if (el) el.textContent = s; };
  const show = (el) => { if (el) el.hidden = false; };
  const hide = (el) => { if (el) el.hidden = true; };
  const cls = (el, name, on) => { if (el) el.classList.toggle(name, !!on); };

  function setPill(state, label) {
    const p = $("#ident-state");
    if (!p) return;
    p.classList.remove("good", "warn", "bad", "dim");
    p.classList.add(state);
    p.textContent = label;
  }

  function setDiag(line) {
    const d = $("#diag");
    if (d) d.textContent = line;
  }

