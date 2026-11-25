  // ── Inline text rendering: links, code, bold, italic ──────────────
  // Tokenize and build DOM nodes - never inject raw HTML.
  // Tokens (in order of priority): triple-backtick blocks, inline `code`,
  // URLs, **bold**, _italic_.
  function renderInlineText(body) {
    const frag = document.createDocumentFragment();
    const blocks = (body || "").split(/```([\s\S]*?)```/g);
    for (let i = 0; i < blocks.length; i++) {
      if (i % 2 === 1) {
        const pre = document.createElement("pre");
        const code = document.createElement("code");
        code.textContent = blocks[i];
        pre.appendChild(code);
        frag.appendChild(pre);
      } else {
        renderInlineNonCode(blocks[i], frag);
      }
    }
    return frag;
  }

  // v0.21.x file-bubble open: click a complete FILE bubble (sender
  // OR receiver) to see the file. For images we open an inline
  // lightbox; for everything else the file is opened in a new tab
  // (the browser then renders it inline or downloads it depending
  // on type). The sender side resolves the file from
  // state.outboundFileCache (browser holds the original File until
  // tab close); the receiver side hits /api/files/<name> which the
  // daemon serves from inbox_dir. When neither path is available
  // the bubble surfaces a calm hint instead of dead-clicking.
  function _outboundFileKey(name, size) {
    return `${(name || "").toLowerCase()}|${size || 0}`;
  }
  function rememberOutboundFile(file) {
    if (!file || !file.name) return;
    const key = _outboundFileKey(file.name, file.size);
    const prev = state.outboundFileCache.get(key);
    if (prev?.objectUrl) {
      try { URL.revokeObjectURL(prev.objectUrl); } catch (_) {}
    }
    state.outboundFileCache.set(key, {
      file,
      addedAt: Date.now(),
      objectUrl: null,
    });
  }
  function objectUrlForOutboundFile(name, size, transferId) {
    // Hot path: the original File object is still in tab memory
    // (uploaded this session). Return a blob: URL pointing at it.
    const key = _outboundFileKey(name, size);
    const ent = state.outboundFileCache.get(key);
    if (ent) {
      if (!ent.objectUrl) ent.objectUrl = URL.createObjectURL(ent.file);
      return ent.objectUrl;
    }
    // Fallback for after-refresh: the daemon's transfer ledger
    // remembers the original disk path of every file we've sent.
    // /api/outbound_files/{transfer_id} streams it back. Skipped when
    // we don't have a transfer_id (e.g. legacy bubbles before the
    // transfer ledger existed).
    if (transferId) {
      return `/api/outbound_files/${encodeURIComponent(transferId)}`;
    }
    return null;
  }
  // v0.21.x: content-addressed file URL. The chat's display name and
  // the on-disk inbox name diverge (collision suffix, staging prefix,
  // folder-share subdir, or the same name received twice), so name-based
  // serving 404s and the preview falls back to "unavailable" on a file
  // that is plainly on disk. The blob hash is the one id both ends agree
  // on; /api/files/by-blob resolves it via the ledger's exact path. The
  // ?as=<ext> hint lets the server pick a Content-Type for extension-less
  // blob-store files.
  function _fileExtHint(name) {
    const m = /\.([A-Za-z0-9]{1,8})$/.exec(name || "");
    return m ? m[1].toLowerCase() : "";
  }
  function blobFileUrl(blob, name) {
    if (!blob) return "";
    const hex = String(blob).toLowerCase();
    if (!/^[0-9a-f]{1,64}$/.test(hex)) return "";
    const base = `/api/files/by-blob/${encodeURIComponent(hex)}`;
    const ext = _fileExtHint(name);
    return ext ? `${base}?as=${encodeURIComponent(ext)}` : base;
  }
  function fileAccessInfoForMessage(msg, t) {
    const name = msg?.name || t?.name || "";
    const fname = name || "file";
    const size = msg?.size || t?.total_bytes || t?.size || 0;
    if (msg?.dir === "in") {
      const blobUrl = blobFileUrl(msg?.blob || t?.blob_hash, fname);
      return {
        url: blobUrl || `/api/files/${encodeURIComponent(fname)}`,
        route: blobUrl ? "Receiver content-hash endpoint" : "Receiver inbox endpoint",
        source: "This computer's received-file store",
        problem: "",
      };
    }
    const url = objectUrlForOutboundFile(fname, size, t?.id);
    if (url) {
      return {
        url,
        route: url.startsWith("blob:") ? "Sender browser cache" : "Sender transfer ledger endpoint",
        source: url.startsWith("blob:") ? "Original file object in this tab" : "Daemon transfer ledger",
        problem: "",
      };
    }
    return {
      url: "",
      route: "No local open route",
      source: "Transfer completed, but this tab does not have the original file handle.",
      problem: "Use Save/Open on the receiving computer, or resend the file to restore a sender-side preview.",
    };
  }
  // Lightbox singleton. Created on first use, reused thereafter.
  function _ensureLightbox() {
    let lb = document.getElementById("file-lightbox");
    if (lb) return lb;
    lb = document.createElement("div");
    lb.id = "file-lightbox";
    lb.className = "file-lightbox";
    lb.setAttribute("role", "dialog");
    lb.setAttribute("aria-modal", "true");
    lb.setAttribute("aria-label", "Image viewer");
    const backdrop = document.createElement("div");
    backdrop.className = "file-lightbox-backdrop";
    backdrop.setAttribute("data-lb-close", "");
    lb.appendChild(backdrop);
    const pane = document.createElement("div");
    pane.className = "file-lightbox-pane";
    pane.setAttribute("role", "document");
    lb.appendChild(pane);
    const head = document.createElement("div");
    head.className = "file-lightbox-head";
    pane.appendChild(head);
    const nameEl = document.createElement("div");
    nameEl.className = "file-lightbox-name";
    head.appendChild(nameEl);
    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "file-lightbox-close";
    closeBtn.setAttribute("data-lb-close", "");
    closeBtn.setAttribute("aria-label", "Close");
    closeBtn.textContent = "x";
    head.appendChild(closeBtn);
    const body = document.createElement("div");
    body.className = "file-lightbox-body";
    pane.appendChild(body);
    const foot = document.createElement("div");
    foot.className = "file-lightbox-foot";
    pane.appendChild(foot);
    const openLink = document.createElement("a");
    openLink.className = "file-lightbox-open";
    openLink.target = "_blank";
    openLink.rel = "noopener noreferrer";
    openLink.textContent = "Open in new tab";
    foot.appendChild(openLink);
    const downloadLink = document.createElement("a");
    downloadLink.className = "file-lightbox-download";
    downloadLink.setAttribute("download", "");
    downloadLink.textContent = "Save a copy";
    foot.appendChild(downloadLink);
    document.body.appendChild(lb);
    lb.addEventListener("click", (ev) => {
      const t = ev.target;
      if (t && t instanceof Element && t.hasAttribute("data-lb-close")) {
        closeLightbox();
      }
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && lb.classList.contains("show")) {
        closeLightbox();
      }
    });
    return lb;
  }
  // v0.21.x: lightbox is gallery-aware. When opened on an image
  // bubble in a conversation, it computes the set of other images
  // in that conversation and lets left / right / swipe move between them
  // without closing. Falls back to single-image mode if no
  // conversation context is supplied.
  const _lightboxState = { gallery: [], index: 0 };
  function openLightbox({ url, name, sizeBytes, downloadName, gallery, index }) {
    const lb = _ensureLightbox();
    _ensureLightboxNavButtons();
    if (Array.isArray(gallery) && gallery.length > 0) {
      _lightboxState.gallery = gallery;
      _lightboxState.index = Math.max(0, Math.min(gallery.length - 1, index || 0));
    } else {
      _lightboxState.gallery = [{ url, name, sizeBytes, downloadName }];
      _lightboxState.index = 0;
    }
    _paintLightbox();
    _attachLightboxNav();
    lb.classList.add("show");
    document.body.classList.add("lb-open");
  }
  function _paintLightbox() {
    const lb = document.getElementById("file-lightbox");
    if (!lb) return;
    const ent = _lightboxState.gallery[_lightboxState.index];
    if (!ent) return;
    const count = _lightboxState.gallery.length;
    const indexLabel = count > 1
      ? ` - ${_lightboxState.index + 1} of ${count}`
      : "";
    lb.querySelector(".file-lightbox-name").textContent = (ent.name || "image")
      + (ent.sizeBytes ? ` - ${fmtBytes(ent.sizeBytes)}` : "")
      + indexLabel;
    const body = lb.querySelector(".file-lightbox-body");
    body.replaceChildren();
    const img = document.createElement("img");
    img.alt = ent.name || "image";
    img.className = "file-lightbox-img";
    img.onerror = () => {
      const err = el("div", "file-lightbox-error");
      err.appendChild(el("div", "title", "Image preview unavailable"));
      err.appendChild(el("div", "hint",
        "Preview unavailable on this device. One Link has the transfer record, but the local preview route did not return image bytes. Open in new tab or save a copy, or retry from the message details."));
      const rows = el("div", "file-detail-rows");
      rows.appendChild(_fileDetailRow("File", ent.name || "image"));
      rows.appendChild(_fileDetailRow("Size", ent.sizeBytes ? fmtBytes(ent.sizeBytes) : "-"));
      rows.appendChild(_fileDetailRow("Preview route", ent.url || "No local preview route"));
      rows.appendChild(_fileDetailRow("What to try", "Open in new tab, save a copy, or retry preview from the chat bubble."));
      err.appendChild(rows);
      body.replaceChildren(err);
    };
    body.appendChild(img);
    img.src = ent.url;
    const openA = lb.querySelector(".file-lightbox-open");
    openA.href = ent.url;
    const dlA = lb.querySelector(".file-lightbox-download");
    dlA.href = ent.url;
    dlA.setAttribute("download", ent.downloadName || ent.name || "file");
    // Nav button visibility - hidden when there's only one image.
    const prev = lb.querySelector(".file-lightbox-prev");
    const next = lb.querySelector(".file-lightbox-next");
    if (prev) prev.style.display = count > 1 ? "" : "none";
    if (next) next.style.display = count > 1 ? "" : "none";
  }
  function _stepLightbox(delta) {
    const count = _lightboxState.gallery.length;
    if (count <= 1) return;
    _lightboxState.index = (_lightboxState.index + delta + count) % count;
    _paintLightbox();
  }
  function _ensureLightboxNavButtons() {
    const lb = document.getElementById("file-lightbox");
    if (!lb || lb.querySelector(".file-lightbox-prev")) return;
    const prev = document.createElement("button");
    prev.type = "button";
    prev.className = "file-lightbox-prev";
    prev.setAttribute("aria-label", "Previous image");
    prev.textContent = "<";
    prev.onclick = (ev) => { ev.stopPropagation(); _stepLightbox(-1); };
    const next = document.createElement("button");
    next.type = "button";
    next.className = "file-lightbox-next";
    next.setAttribute("aria-label", "Next image");
    next.textContent = ">";
    next.onclick = (ev) => { ev.stopPropagation(); _stepLightbox(1); };
    lb.appendChild(prev);
    lb.appendChild(next);
  }
  function _attachLightboxNav() {
    const lb = document.getElementById("file-lightbox");
    if (!lb || lb._navAttached) return;
    lb._navAttached = true;
    document.addEventListener("keydown", (ev) => {
      if (!lb.classList.contains("show")) return;
      if (ev.key === "ArrowLeft") { ev.preventDefault(); _stepLightbox(-1); }
      else if (ev.key === "ArrowRight") { ev.preventDefault(); _stepLightbox(1); }
    });
    // Touch swipe
    let startX = 0, startY = 0, tracking = false;
    const body = lb.querySelector(".file-lightbox-body");
    body.addEventListener("touchstart", (ev) => {
      const t = ev.touches[0]; startX = t.clientX; startY = t.clientY; tracking = true;
    }, { passive: true });
    body.addEventListener("touchend", (ev) => {
      if (!tracking) return; tracking = false;
      const t = ev.changedTouches[0];
      const dx = t.clientX - startX;
      const dy = t.clientY - startY;
      if (Math.abs(dx) > 40 && Math.abs(dx) > Math.abs(dy)) {
        _stepLightbox(dx > 0 ? -1 : 1);
      }
    }, { passive: true });
  }
  // v0.21.x: build a gallery for the current conversation by
  // walking state.messages for image-typed bubbles. Each entry maps
  // to the inbound /api/files URL or the outbound cached blob URL.
  function _buildLightboxGalleryForCurrent(currentMsg) {
    const peerShortId = currentMsg.peer;
    if (!peerShortId) return null;
    const entries = [];
    let activeIdx = 0;
    const all = state.messages.filter((m) =>
      m.peer === peerShortId
      && (m.t === "FILE_OFFER" || m.t === "FILE_DONE")
      && isImageName(m.name));
    for (const m of all) {
      let url = null;
      let downloadName = m.name || "";
      if (m.dir === "in") {
        const fname = (m.path || m.name || "").toString().split(/[\\\/]/).pop();
        const blobUrl = blobFileUrl(m.blob, m.name || fname);
        url = blobUrl || (fname ? `/api/files/${encodeURIComponent(fname)}` : null);
        downloadName = fname || m.name || "image";
      } else {
        const t = transferForMessage(m);
        url = objectUrlForOutboundFile(m.name, m.size || 0, t?.id);
      }
      if (!url) continue;
      if (m.id === currentMsg.id) activeIdx = entries.length;
      entries.push({
        url,
        name: m.name || "image",
        sizeBytes: m.size || 0,
        downloadName,
      });
    }
    if (entries.length === 0) return null;
    return { gallery: entries, index: activeIdx };
  }
  function closeLightbox() {
    const lb = document.getElementById("file-lightbox");
    if (!lb) return;
    lb.classList.remove("show");
    document.body.classList.remove("lb-open");
    const body = lb.querySelector(".file-lightbox-body");
    if (body) body.replaceChildren();
  }
  // Open the file referenced by `msg` (a TEXT-shaped FILE_OFFER or
  // FILE_DONE event). Picks the right source: receiver → daemon's
  // /api/files; sender → cached File object. Picks the right
  // viewer: image → lightbox; everything else → new tab.
  function openMessageFile(msg) {
    const name = msg.name || "file";
    const size = msg.size || 0;
    const isImage = isImageName(name);
    let url = null;
    let downloadName = name;
    if (msg.dir === "in") {
      const fname = (msg.path || name || "").toString().split(/[\\\/]/).pop();
      const blobUrl = blobFileUrl(msg.blob, name || fname);
      url = blobUrl || (fname ? `/api/files/${encodeURIComponent(fname)}` : null);
      if (!url) {
        toast("Couldn't find the file on disk.", "info", 4000);
        return;
      }
      downloadName = fname || name;
    } else if (msg.dir === "out") {
      const t = transferForMessage(msg);
      url = objectUrlForOutboundFile(name, size, t?.id);
      if (!url) {
        // No browser-side File AND no transfer_id we can ask the
        // daemon for — should only happen on legacy pre-ledger
        // bubbles. Be honest about the cause.
        toast(
          "Can't preview this file. It predates the transfer ledger, "
          + "so the daemon doesn't remember where it lived on disk. "
          + "Drag the original in again to share another copy.",
          "info", 6000,
        );
        return;
      }
    }
    if (!url) return;
    if (isImage) {
      // v0.21.x: prefer gallery mode so ← / → swipe through every
      // image in this conversation. Falls back to single-image when
      // we can't compute the gallery (e.g. orphan bubble).
      const gal = _buildLightboxGalleryForCurrent(msg);
      if (gal) {
        openLightbox({ gallery: gal.gallery, index: gal.index });
      } else {
        openLightbox({ url, name, sizeBytes: size, downloadName });
      }
    } else {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  }

  // Long message bodies clutter the chat the way a pasted log or
  // wall-of-text does in Claude. Collapse anything past the
  // thresholds below into a preview with a Show more / Show less
  // toggle so the bubble stays a glance-able height by default.
  // The text is fully rendered (and selectable) in both states —
  // collapsed just hides the overflow under a CSS mask. Per-message
  // ephemeral state; nothing persisted.
  const COLLAPSE_CHARS = 600;
  const COLLAPSE_LINES = 8;
  // 2026-06-04: detect when a message has block-level markdown
  // structure (headings, lists, blockquotes, fenced code, rules).
  // Casual messages with no markers still go through the lighter
  // inline path so they don't get rewrapped as <p> tags. Anything
  // a user is likely to PASTE (a writeup, a doc, a Claude/ChatGPT
  // answer) almost always has one of these markers and lights up
  // the full markdown renderer for proper structure.
  const _MD_BLOCK_RE = /^(?:#{1,6}\s|[-*+]\s|\d+\.\s|>\s?|```|(-{3,}|\*{3,}|_{3,})\s*$)/m;
  function _looksLikeMarkdown(text) {
    if (!text) return false;
    return _MD_BLOCK_RE.test(text);
  }
  function _renderChatBody(text) {
    if (_looksLikeMarkdown(text)) {
      const node = renderMarkdownDoc(text);
      // Tag so chat-specific CSS overrides apply (tighter margins,
      // smaller heading sizes than the file-preview pane).
      node.classList.add("md-chat");
      return node;
    }
    return renderInlineText(text);
  }
  function appendCollapsibleText(parent, body) {
    const text = body || "";
    const lines = text.split("\n").length;
    const long = text.length > COLLAPSE_CHARS || lines > COLLAPSE_LINES;
    if (!long) {
      parent.appendChild(_renderChatBody(text));
      return;
    }
    const wrap = document.createElement("div");
    wrap.className = "msg-body collapsible collapsed";
    wrap.appendChild(_renderChatBody(text));
    parent.appendChild(wrap);
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "body-toggle";
    toggle.textContent = "Show more";
    toggle.title = `Message is ${text.length.toLocaleString()} characters`;
    toggle.onclick = (ev) => {
      ev.stopPropagation();
      if (wrap.classList.contains("collapsed")) {
        wrap.classList.remove("collapsed");
        toggle.textContent = "Show less";
      } else {
        wrap.classList.add("collapsed");
        toggle.textContent = "Show more";
      }
    };
    parent.appendChild(toggle);
  }
  function renderInlineNonCode(text, frag) {
    const parts = text.split(/`([^`\n]+)`/g);
    for (let i = 0; i < parts.length; i++) {
      if (i % 2 === 1) {
        const c = document.createElement("code");
        c.textContent = parts[i];
        frag.appendChild(c);
      } else {
        renderInlineMarks(parts[i], frag);
      }
    }
  }
  function renderInlineMarks(text, frag) {
    // Collect non-overlapping ranges for url / link / bold / italic /
    // strikethrough. ``LINK_RE`` is checked BEFORE the autolink URL_RE
    // so a markdown [text](url) match wins over the raw-URL fallback;
    // the ranges.sort + dedup pass below also drops any URL match
    // that overlaps an earlier link.
    const URL_RE   = /\bhttps?:\/\/[^\s<>"')\]]+|\bwww\.[^\s<>"')\]]+/gi;
    const LINK_RE  = /\[([^\]\n]+)\]\(([^)\s]+)\)/g;
    const BOLD_RE  = /\*\*([^*\n]+)\*\*/g;
    const ITAL_RE  = /(?:^|[\s(\[{])_([^_\n]+)_(?=$|[\s).,!?:;\]}])/g;
    const STRIKE_RE = /~~([^~\n]+)~~/g;
    const ranges = [];
    let m;
    while ((m = LINK_RE.exec(text))  !== null) ranges.push({s: m.index, e: m.index + m[0].length, t: "link", raw: m[1], href: m[2]});
    while ((m = URL_RE.exec(text))   !== null) ranges.push({s: m.index, e: m.index + m[0].length, t: "url",  raw: m[0]});
    while ((m = BOLD_RE.exec(text))  !== null) ranges.push({s: m.index, e: m.index + m[0].length, t: "bold", raw: m[1]});
    while ((m = ITAL_RE.exec(text))  !== null) {
      // Italic match includes a leading whitespace/open-bracket; offset start.
      const lead = m[0].length - (m[1].length + 2);
      ranges.push({s: m.index + lead, e: m.index + m[0].length, t: "ital", raw: m[1]});
    }
    while ((m = STRIKE_RE.exec(text)) !== null) ranges.push({s: m.index, e: m.index + m[0].length, t: "strike", raw: m[1]});
    // Sort with link/url winning the tie so a URL captured inside a
    // markdown link's URL slot doesn't double-render.
    ranges.sort((a, b) => a.s - b.s || (a.e - b.e));
    const kept = [];
    let cursor = 0;
    for (const r of ranges) {
      if (r.s < cursor) continue;
      kept.push(r);
      cursor = r.e;
    }
    function _safeHref(href) {
      // Reject javascript:/data: URIs. Anything else (http, https,
      // mailto, even relative paths) is fine.
      const trimmed = String(href || "").trim();
      if (/^(javascript:|data:|vbscript:)/i.test(trimmed)) return null;
      return trimmed;
    }
    let pos = 0;
    for (const r of kept) {
      if (r.s > pos) frag.appendChild(document.createTextNode(text.slice(pos, r.s)));
      if (r.t === "link") {
        const href = _safeHref(r.href);
        if (!href) {
          // Unsafe scheme — render as plain text, no anchor.
          frag.appendChild(document.createTextNode(text.slice(r.s, r.e)));
        } else {
          const a = document.createElement("a");
          a.href = href;
          a.textContent = r.raw;
          a.target = "_blank";
          a.rel = "noopener noreferrer";
          frag.appendChild(a);
        }
      } else if (r.t === "url") {
        const a = document.createElement("a");
        const href = r.raw.startsWith("www.") ? "https://" + r.raw : r.raw;
        a.href = href;
        a.textContent = r.raw;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        frag.appendChild(a);
      } else if (r.t === "bold") {
        const b = document.createElement("strong");
        b.textContent = r.raw;
        frag.appendChild(b);
      } else if (r.t === "ital") {
        const i = document.createElement("em");
        i.textContent = r.raw;
        frag.appendChild(i);
      } else if (r.t === "strike") {
        const s = document.createElement("s");
        s.textContent = r.raw;
        frag.appendChild(s);
      }
      pos = r.e;
    }
    if (pos < text.length) frag.appendChild(document.createTextNode(text.slice(pos)));
  }

