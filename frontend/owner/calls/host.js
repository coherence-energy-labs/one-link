  // ── Owner-page services, through their explicit bridge (MNT-03) ──
  // This driver is its own closure: the owner page's `api`, `toast`,
  // `selectPeer` and other helpers are not in scope here, and naming them
  // directly is a ReferenceError (it silently broke the privacy preset
  // switch, in-call file send and call-end teardown). The owner page
  // publishes exactly the services the driver uses as
  // window.__oneLinkCallHost; these adapters are the only route to them.
  // Without a host page, toasts and navigation are skipped and requests
  // reject, so each caller's own error path runs.
  function _callHost() {
    return (typeof window !== "undefined" && window.__oneLinkCallHost) || null;
  }
  function _requireCallHost(what) {
    const host = _callHost();
    if (!host) throw new Error(`${what} needs the One Link owner page`);
    return host;
  }
  const api = Object.freeze({
    post: async (path, body) => _requireCallHost("This request").post(path, body),
    upload: async (peerId, file, opts) => _requireCallHost("Sending a file").upload(peerId, file, opts),
  });
  function toast(message, kind, ms) {
    const host = _callHost();
    if (host) host.toast(message, kind, ms);
  }
  function errorToastBody(error) {
    const host = _callHost();
    if (host) return host.errorToastBody(error);
    return (error && error.message) ? error.message : String(error);
  }
  function _newClientMsgId() {
    return _requireCallHost("A file intent").newClientMsgId();
  }
  function returnToOneHealthGuideIfPending() {
    const host = _callHost();
    return host ? host.returnToOneHealthGuideIfPending() : false;
  }
  function selectPeer(peerId) {
    const host = _callHost();
    if (host) host.selectPeer(peerId);
  }
  // Server-controlled text inserted as HTML (2026-05-21 audit T3-A). Kept
  // local: escaping must never depend on another page being present. The
  // owner page's _escapeHtml is the same five replacements; a contract
  // test compares the two on adversarial input.
  function _escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
