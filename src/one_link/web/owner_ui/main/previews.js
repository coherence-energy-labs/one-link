  // ── Inline previews (v0.9.0) ───────────────────────────────────────
  // Whitelist mirrors server-side PREVIEW_KINDS - keep in sync.
  const PREVIEW_KINDS = new Map([
    ["pdf","pdf"],
    // v0.21.x: video / audio / svg / html stream-preview kinds
    ["mp4","video"],["webm","video"],["mov","video"],["m4v","video"],
    ["mkv","video"],["ogv","video"],
    ["mp3","audio"],["wav","audio"],["ogg","audio"],["oga","audio"],
    ["m4a","audio"],["aac","audio"],["flac","audio"],["opus","audio"],
    ["svg","image"],
    ["html","html-sandboxed"],["htm","html-sandboxed"],
    ["md","markdown"],["markdown","markdown"],["mdown","markdown"],
    ["py","code"],["js","code"],["mjs","code"],["cjs","code"],
    ["ts","code"],["tsx","code"],["jsx","code"],
    ["css","code"],["scss","code"],["sass","code"],["less","code"],
    ["json","code"],["yaml","code"],["yml","code"],["toml","code"],
    ["xml","code"],["ini","code"],["conf","code"],["cfg","code"],
    ["sh","code"],["bash","code"],["zsh","code"],["fish","code"],
    ["ps1","code"],["bat","code"],
    ["rb","code"],["go","code"],["rs","code"],["java","code"],
    ["kt","code"],["swift","code"],["scala","code"],
    ["c","code"],["h","code"],["cc","code"],["cpp","code"],["hpp","code"],
    ["lua","code"],["r","code"],["pl","code"],["php","code"],
    ["sql","code"],["graphql","code"],["proto","code"],
    ["txt","text"],["log","text"],["csv","text"],["tsv","text"],
    ["env","text"],["gitignore","text"],["gitattributes","text"],
    ["license","text"],["readme","text"],
  ]);
  function previewKindForName(name) {
    if (!name) return null;
    const ext = (name.split(".").pop() || "").toLowerCase();
    return PREVIEW_KINDS.get(ext) || null;
  }

  // v0.9.0: minimal markdown renderer scoped to previews.
  // Supports: ATX headings (# ##), paragraphs, fenced code blocks,
  // blockquotes, ordered + unordered lists (single-level), horizontal
  // rules. Inline syntax delegates to renderInlineNonCode (bold,
  // italic, inline code, autolinks). Deliberately small + safe - no
  // raw HTML escape hatch, so no XSS surface.
  function renderMarkdownDoc(source) {
    const root = el("div", "md-preview");
    const lines = (source || "").split(/\r?\n/);
    let i = 0;
    const n = lines.length;
    while (i < n) {
      const ln = lines[i];
      if (/^```/.test(ln.trimStart())) {
        // Fenced code block
        const lang = ln.trimStart().slice(3).trim();
        const buf = [];
        i += 1;
        while (i < n && !/^```/.test(lines[i].trimStart())) {
          buf.push(lines[i]);
          i += 1;
        }
        const pre = document.createElement("pre");
        const code = document.createElement("code");
        if (lang) code.dataset.lang = lang;
        code.textContent = buf.join("\n");
        pre.appendChild(code);
        root.appendChild(pre);
        if (i < n) i += 1;  // skip closing fence
        continue;
      }
      const headM = ln.match(/^(#{1,6})\s+(.*)$/);
      if (headM) {
        const lvl = headM[1].length;
        const h = document.createElement("h" + lvl);
        renderInlineNonCode(headM[2].trim(), h);
        root.appendChild(h);
        i += 1;
        continue;
      }
      if (/^(-{3,}|\*{3,}|_{3,})\s*$/.test(ln)) {
        root.appendChild(document.createElement("hr"));
        i += 1;
        continue;
      }
      if (/^>\s?/.test(ln)) {
        // Blockquote - collect contiguous > lines.
        const buf = [];
        while (i < n && /^>\s?/.test(lines[i])) {
          buf.push(lines[i].replace(/^>\s?/, ""));
          i += 1;
        }
        const bq = document.createElement("blockquote");
        renderInlineNonCode(buf.join("\n"), bq);
        root.appendChild(bq);
        continue;
      }
      const ulM = ln.match(/^([-*+])\s+(.*)$/);
      const olM = ln.match(/^(\d+)\.\s+(.*)$/);
      if (ulM || olM) {
        const ordered = !!olM;
        const list = document.createElement(ordered ? "ol" : "ul");
        while (i < n) {
          const L = lines[i];
          const m = ordered ? L.match(/^(\d+)\.\s+(.*)$/) : L.match(/^([-*+])\s+(.*)$/);
          if (!m) break;
          const li = document.createElement("li");
          renderInlineNonCode(m[2], li);
          list.appendChild(li);
          i += 1;
        }
        root.appendChild(list);
        continue;
      }
      if (ln.trim() === "") { i += 1; continue; }
      // Paragraph - collect lines until blank or block boundary.
      const buf = [ln];
      i += 1;
      while (i < n) {
        const L = lines[i];
        if (L.trim() === "") break;
        if (/^(#{1,6}\s|>\s|```|[-*+]\s|\d+\.\s|(-{3,}|\*{3,}|_{3,})\s*$)/.test(L.trimStart())) break;
        buf.push(L);
        i += 1;
      }
      const p = document.createElement("p");
      renderInlineNonCode(buf.join(" "), p);
      root.appendChild(p);
    }
    return root;
  }

  // v0.9.0: code preview with line numbers. No syntax highlighting
  // (vendoring a highlighter would 10x the bundle); monospace +
  // line-numbered gutter is plenty for "what's in this script?".
  function renderCodePreview(source, ext) {
    const wrap = el("div", "code-preview");
    if (ext) wrap.dataset.lang = ext;
    const lines = (source || "").split("\n");
    const gutter = el("div", "gutter");
    const code = el("pre", "code-body");
    for (let i = 0; i < lines.length; i++) {
      gutter.appendChild(el("span", "ln", String(i + 1)));
    }
    const codeEl = document.createElement("code");
    codeEl.textContent = source || "";
    code.appendChild(codeEl);
    wrap.appendChild(gutter);
    wrap.appendChild(code);
    return wrap;
  }

  function renderTextPreview(source) {
    const wrap = el("div", "text-preview");
    const pre = document.createElement("pre");
    pre.textContent = source || "";
    wrap.appendChild(pre);
    return wrap;
  }

  // v0.9.5: PDF preview via the browser's native viewer. We render
  // an <iframe> pointing at /api/files/{name} - Chrome/Edge/Safari/
  // Firefox all ship with built-in PDF support, so we don't need to
  // vendor PDF.js (~600 KB). The fourth-arg streamUrl is the path
  // the file is served from (passed by the caller in the file-bubble
  // wiring).
  function renderPdfPreview(streamUrl, name) {
    const wrap = el("div", "pdf-preview");
    const frame = document.createElement("iframe");
    frame.src = streamUrl;
    frame.title = name || "PDF preview";
    frame.setAttribute("loading", "lazy");
    // sandbox allows scripts (PDF.js inside Firefox needs them) but
    // not top-navigation or popups.
    frame.setAttribute(
      "sandbox",
      "allow-scripts allow-same-origin allow-popups",
    );
    wrap.appendChild(frame);
    const fallback = el("div", "pdf-fallback");
    const dl = el("a", null, "Open PDF in new tab");
    dl.href = streamUrl;
    dl.target = "_blank";
    dl.rel = "noopener noreferrer";
    fallback.appendChild(document.createTextNode("Browser doesn't render PDFs inline? "));
    fallback.appendChild(dl);
    wrap.appendChild(fallback);
    return wrap;
  }

  // v0.21.x: video preview via HTML5 <video controls>. The daemon
  // streams the file over /api/files/{name}; the browser handles
  // byte-range requests for seek + decoder selection. If a codec
  // is missing the browser's native 'cannot play' UI takes over
  // (no broken iframe sad-face).
  function renderVideoPreview(streamUrl, name) {
    const wrap = el("div", "video-preview");
    const video = document.createElement("video");
    video.src = streamUrl;
    video.controls = true;
    video.preload = "metadata";
    video.setAttribute("playsinline", "");
    video.title = name || "Video preview";
    video.style.maxWidth = "100%";
    video.style.maxHeight = "400px";
    wrap.appendChild(video);
    return wrap;
  }

  // v0.21.x: audio preview via HTML5 <audio controls>. Distinct
  // from the in-app voice-note bubble (which uses .audio-player
  // for waveform + transcript) - this is for attached audio files
  // the sender didn't record via the voice flow.
  function renderAudioPreview(streamUrl, name) {
    const wrap = el("div", "audio-preview");
    const audio = document.createElement("audio");
    audio.src = streamUrl;
    audio.controls = true;
    audio.preload = "metadata";
    audio.title = name || "Audio preview";
    audio.style.width = "100%";
    wrap.appendChild(audio);
    return wrap;
  }

  // v0.21.x: image preview for files (SVG primarily) that aren't
  // already rendered as a first-class image bubble. <img> handles
  // raster + vector natively.
  function renderImagePreview(streamUrl, name) {
    const wrap = el("div", "image-preview");
    const img = document.createElement("img");
    img.src = streamUrl;
    img.alt = name || "Image preview";
    img.loading = "lazy";
    img.style.maxWidth = "100%";
    img.style.maxHeight = "400px";
    img.style.objectFit = "contain";
    wrap.appendChild(img);
    return wrap;
  }

  // v0.21.x: HTML preview in a TIGHTLY-SANDBOXED iframe. We strip
  // allow-same-origin so the embedded document can never read the
  // host's cookies / localStorage / IndexedDB, can never make
  // authenticated fetches back to the daemon, and can never
  // synchronously navigate the parent. Scripts ARE allowed (an
  // HTML file with no JS is rare); allow-popups lets <a target="_blank">
  // links open. Worst case: a sender plants malicious HTML, the
  // browser runs it in a credential-less anonymous sandbox.
  function renderHtmlPreview(streamUrl, name) {
    const wrap = el("div", "html-preview");
    const frame = document.createElement("iframe");
    frame.src = streamUrl;
    frame.title = name || "HTML preview";
    frame.setAttribute("loading", "lazy");
    // NOTE: NO allow-same-origin - the credential gap is the point.
    frame.setAttribute("sandbox", "allow-scripts allow-popups");
    frame.style.width = "100%";
    frame.style.height = "400px";
    frame.style.border = "1px solid var(--bg-3)";
    frame.style.borderRadius = "8px";
    wrap.appendChild(frame);
    const note = el("div", "preview-note",
      "HTML rendered in a sandbox - no access to your One Link cookies.");
    note.style.fontSize = "11px";
    note.style.color = "var(--text-dim)";
    note.style.marginTop = "4px";
    wrap.appendChild(note);
    return wrap;
  }

  function renderPreviewByKind(kind, content, ext, opts) {
    if (kind === "markdown") return renderMarkdownDoc(content);
    if (kind === "code") return renderCodePreview(content, ext);
    if (kind === "pdf") {
      return renderPdfPreview(opts?.streamUrl || "", opts?.name || "");
    }
    if (kind === "video") {
      return renderVideoPreview(opts?.streamUrl || "", opts?.name || "");
    }
    if (kind === "audio") {
      return renderAudioPreview(opts?.streamUrl || "", opts?.name || "");
    }
    if (kind === "image") {
      return renderImagePreview(opts?.streamUrl || "", opts?.name || "");
    }
    if (kind === "html-sandboxed") {
      return renderHtmlPreview(opts?.streamUrl || "", opts?.name || "");
    }
    return renderTextPreview(content);
  }

  // Look up the transfer record matching a FILE_OFFER message.
  // FILE_OFFER carries `blob` (hex); transfer carries `blob_hash`.
  // Direction must match too (out vs in are distinct ledger rows).
  // 2026-05-21 audit T3-Z: lookups for "is this file message
  // associated with a known transfer" used to be O(N×M) — walking
  // every entry of ``state.transfersById`` once per file bubble per
  // re-render (~16k iterations/frame at typical scale). Maintain a
  // secondary index ``state.transferByDirBlob`` keyed by
  // ``"<dir>|<blob_hash>"`` so the lookup becomes O(1). Rebuilt
  // whenever ``state.transfersById`` is mutated.
