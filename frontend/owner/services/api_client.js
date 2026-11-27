// Isolated service: dependencies are explicit parameters; no owner closure access.
function createOwnerApiClient({
  fetch,
  _maybe401,
  _apiError,
  _newClientMsgId,
  AbortController,
  FormData,
  Blob,
  setTimeout,
  clearTimeout,
}) {
  // Last line of defence for every file-send surface, including onboarding,
  // voice, call UI, and future direct callers.  A concrete File + immutable
  // presentation contract owns one browser idempotency key, and concurrent
  // calls coalesce onto one fetch.  Failed/lost responses retain the key so a
  // retry of that same File cannot accidentally mint a second wire intent.
  const _implicitUploadIntents = new WeakMap();
  function _uploadIntentEntry(peer, file, opts) {
    if (!file || (typeof file !== "object" && typeof file !== "function")) {
      return { clientDeliveryId: opts.clientDeliveryId || _newClientMsgId(), inFlight: null };
    }
    let byContract = _implicitUploadIntents.get(file);
    if (!byContract) {
      byContract = new Map();
      _implicitUploadIntents.set(file, byContract);
    }
    const contractKey = JSON.stringify([
      String(peer || ""),
      String(opts.relPath || ""),
      opts.chatInline !== false,
      opts.clientDeliveryId || null,
    ]);
    let entry = byContract.get(contractKey);
    if (!entry) {
      entry = {
        clientDeliveryId: opts.clientDeliveryId || _newClientMsgId(),
        inFlight: null,
      };
      byContract.set(contractKey, entry);
    }
    return entry;
  }

  // A polling UI has several legitimate consumers of the same snapshots
  // (for example Status, Activity, and the transfer pane). Coalesce only
  // requests that are concurrently in flight: callers still get fresh data
  // on the next poll, while aligned timers cannot stampede the daemon.
  const _apiGetInFlight = new Map();
  const api = {
    async get(p, opts = {}) {
      const coalesce = opts.coalesce !== false;
      const requestKey = `${String(p)}\u0000${Number(opts.timeoutMs || 0)}`;
      if (coalesce && _apiGetInFlight.has(requestKey)) {
        return await _apiGetInFlight.get(requestKey);
      }
      const operation = (async () => {
        const ctrl = opts.timeoutMs ? new AbortController() : null;
        const timer = ctrl ? setTimeout(
          () => ctrl.abort(),
          opts.timeoutMs,
        ) : null;
        try {
          const r = await fetch(p, {
            credentials: "include",
            signal: ctrl ? ctrl.signal : undefined,
          });
          _maybe401(r.status);
          if (!r.ok) {
            // v0.21.x: route GET errors through _apiError so the
            // user-visible message comes from the server's JSON
            // (error, hint, code) rather than a raw URL-path-and-
            // status leak. Falls back gracefully when the body
            // isn't JSON (which is fine - _apiError synthesizes a
            // generic 'request failed (status)' headline).
            const j = await r.json().catch(() => ({}));
            throw _apiError(j, r.status);
          }
          return r.json();
        } finally {
          if (timer) clearTimeout(timer);
        }
      })();
      if (coalesce) _apiGetInFlight.set(requestKey, operation);
      try {
        return await operation;
      } finally {
        if (coalesce && _apiGetInFlight.get(requestKey) === operation) {
          _apiGetInFlight.delete(requestKey);
        }
      }
    },
    async post(p, body, opts = {}) {
      // v0.21.x: optional hard timeout so fetch() can never hang
      // forever. Critical for /api/send: a wedged channel used to
      // freeze the Send button silently — no toast, no clear, no
      // recourse. With timeoutMs set, AbortError raises after the
      // budget, and _sendWithOutbox falls through to the queue
      // path (recognising AbortError as network-like).
      const ctrl = opts.timeoutMs ? new AbortController() : null;
      const timer = ctrl ? setTimeout(
        () => ctrl.abort(),
        opts.timeoutMs,
      ) : null;
      try {
        const r = await fetch(p, {
          method: "POST",
          credentials: "include",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(body),
          signal: ctrl ? ctrl.signal : undefined,
        });
        _maybe401(r.status);
        const j = await r.json().catch(()=>({}));
        if (!r.ok) throw _apiError(j, r.status);
        return j;
      } finally {
        if (timer) clearTimeout(timer);
      }
    },
    async postForm(p, fields, opts = {}) {
      const ctrl = opts.timeoutMs ? new AbortController() : null;
      const timer = ctrl ? setTimeout(() => ctrl.abort(), opts.timeoutMs) : null;
      try {
        const form = new FormData();
        for (const [name, value] of Object.entries(fields || {})) {
          if (value instanceof Blob) {
            form.append(name, value, value.name || "upload.bin");
          } else if (value !== undefined && value !== null) {
            form.append(name, String(value));
          }
        }
        const r = await fetch(p, {
          method: "POST",
          credentials: "include",
          body: form,
          signal: ctrl ? ctrl.signal : undefined,
        });
        _maybe401(r.status);
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw _apiError(j, r.status);
        return j;
      } finally {
        if (timer) clearTimeout(timer);
      }
    },
    async del(p) {
      const r = await fetch(p, { method: "DELETE", credentials: "include" });
      _maybe401(r.status);
      const j = await r.json().catch(()=>({}));
      if (!r.ok) throw _apiError(j, r.status);
      return j;
    },
    async upload(peer, file, opts = {}) {
      const intent = _uploadIntentEntry(peer, file, opts);
      if (intent.inFlight) return await intent.inFlight;
      const operation = (async () => {
        const fd = new FormData();
        fd.append("peer", peer);
        // Stable browser-side idempotency key.  A staged item keeps this value
        // across response loss/retry; the daemon durably binds it to the exact
        // peer + content + presentation contract before emitting FILE_OFFER.
        fd.append("client_delivery_id", intent.clientDeliveryId);
        // v0.21.x: optional rel_path for folder-tree-preserving uploads
        // (drag-folder drop in chat UI). Receiver mirrors the tree
        // under inbox/<rel_path>. Falsy values are not sent so single-
        // file uploads keep the original flat behavior.
        if (opts.relPath) fd.append("rel_path", String(opts.relPath));
        // Accept-first: api.upload is the chat-attach path (paste / drop
        // / attach / voice). All current callers are conversational so we
        // default chat_inline ON — the receiver auto-accepts and no
        // prompt fires. A future "send file privately" caller can opt out
        // with chatInline:false.
        if (opts.chatInline !== false) fd.append("chat_inline", "1");
        // Keep the byte stream last. On a lost-response retry the server can
        // authenticate the key + presentation prefix and replay the already
        // committed result without reading or hashing the file again.
        fd.append("file_size", String(file.size));
        fd.append("intent_metadata_complete", "1");
        fd.append("file", file, file.name);
        const r = await fetch("/api/send-file", { method:"POST", credentials:"include", body: fd });
        _maybe401(r.status);
        const j = await r.json().catch(()=>({}));
        if (!r.ok) throw _apiError(j, r.status);
        return j;
      })();
      intent.inFlight = operation;
      try {
        return await operation;
      } finally {
        if (intent.inFlight === operation) intent.inFlight = null;
      }
    },
    folders() { return this.get("/api/folders"); },
    transfers() { return this.get("/api/transfers?limit=80"); },
    status() { return this.get("/api/status"); },
    setup() { return this.get("/api/setup"); },
    setupAction(action) { return this.post("/api/setup", { action }); },
    setupRecoveryPhrase() { return this.post("/api/setup/recovery-phrase", {}); },
    // v0.21.x recovery wizard. Replaces the self-attestation modal
    // (which asked the user to type "I have my recovery info" to
    // confirm something they had no in-app way to actually do)
    // with three real flows backed by /api/v1/recovery/*.
    recoveryStatus() { return this.get("/api/v1/recovery/status"); },
    recoveryPhrase() { return this.post("/api/v1/recovery/phrase", {}); },
    recoveryPhraseVerify(indices, words) {
      return this.post("/api/v1/recovery/phrase/verify", { indices, words });
    },
    // Non-destructive 'did I write the phrase down correctly?'
    // check. Decodes the phrase + compares to the current seed
    // without writing any state.
    recoveryPhraseTest(phrase) {
      return this.post("/api/v1/recovery/phrase/test", { phrase });
    },
    // Non-destructive 'does this .olbak decrypt with this phrase?'
    // check. AEAD-decrypts in memory and returns the bundle's
    // header + plaintext file count without writing to disk.
    recoveryBundleTest(phrase, bundleFile) {
      return this.postForm("/api/v1/recovery/bundle/test", {
        phrase, bundle: bundleFile,
      });
    },
    // Non-destructive 'do my guardian shares still reconstruct my
    // identity?' check. Combines K shares in memory + compares the
    // reconstructed seed to the on-disk master.seed without writing
    // anything. Lets a user audit their social-recovery setup
    // periodically without committing to a destructive restore.
    // Accepts either shares=[{index,bytes_b64}] OR the textarea
    // shape share_lines="idx:b64\nidx:b64".
    recoverySharesTest({ shares, shareLines }) {
      const body = {};
      if (Array.isArray(shares)) body.shares = shares;
      if (typeof shareLines === "string") body.share_lines = shareLines;
      return this.post("/api/v1/recovery/shares/test", body);
    },
    // Social-share recovery (guardian side). Import an .olss file
    // someone gave you so your daemon can later unwrap + deliver
    // your share when they need help recovering.
    recoveryHeldSharesList() { return this.get("/api/v1/recovery/shares"); },
    recoveryHeldSharesImport(blobB64, label, ownerHint) {
      return this.post("/api/v1/recovery/shares/import", {
        blob_b64: blobB64, label, owner_hint: ownerHint,
      });
    },
    recoveryHeldSharesDelete(shareId) {
      return this.del(`/api/v1/recovery/shares/${shareId}`);
    },
    recoveryHeldSharesUnwrap(shareId) {
      return this.post(`/api/v1/recovery/shares/${shareId}/unwrap`, {});
    },
    recoverySocialCandidates() { return this.get("/api/v1/recovery/social/candidates"); },
    recoverySocialIssue(guardians, threshold_k) {
      return this.post("/api/v1/recovery/social/issue", { guardians, threshold_k });
    },
    // Backup export streams a binary .olbak file. We bypass the
    // JSON-aware `api.get` wrapper and use fetch directly so we
    // can deliver the bytes to the browser as a download. URL is
    // built as a constant + branch (not a template literal) so the
    // route-contract test sees a clean string, not "${qs}" treated
    // as a path-template placeholder.
    recoveryBackupExportUrl(includeFiles) {
      if (includeFiles) return "/api/v1/recovery/backup/export?include_files=1";
      return "/api/v1/recovery/backup/export";
    },
    // Restore-from-phrase: the OTHER half of recovery. Setup writes
    // the 24 words; restore types them on a new install + brings
    // the identity back. Preflight reports whether the install is
    // clean (one-click restore) or dirty (needs explicit force).
    recoveryRestorePreflight() { return this.get("/api/v1/recovery/restore/preflight"); },
    recoveryRestorePhrase(phrase, force, confirmedReplace) {
      return this.post("/api/v1/recovery/restore/phrase", {
        phrase, force: !!force, confirmed_replace: !!confirmedReplace,
      });
    },
    recoveryRestoreBundle(phrase, bundleFile, force, confirmedReplace) {
      return this.postForm("/api/v1/recovery/restore/bundle", {
        phrase, bundle: bundleFile,
        force: !!force, confirmed_replace: !!confirmedReplace,
      });
    },
    recoveryRestoreShares(shareLines, force, confirmedReplace) {
      return this.post("/api/v1/recovery/restore/shares", {
        share_lines: shareLines,
        force: !!force, confirmed_replace: !!confirmedReplace,
      });
    },
    // v0.21.x identity rotation: mint a new identity, sign a cert
    // with the OLD key, queue per-peer delivery. UI flow prompts
    // the user to back up the new 24 words + restart.
    recoveryRotate(reason) {
      return this.post("/api/v1/recovery/rotate", {
        reason, confirmed_rotate: true,
      });
    },
    recoveryRotatePendingPhrase(expectedNewFp) {
      return this.post("/api/v1/recovery/rotate/pending-phrase", {
        expected_new_fp: expectedNewFp, confirmed_view: true,
      });
    },
    recoveryRotateStatus() { return this.get("/api/v1/recovery/rotate/status"); },
    recoveryReset() { return this.post("/api/v1/recovery/reset", { confirmed_reset: true }); },
    // Graceful shutdown so 'Restart One Link to take effect' after
    // rotation / restore can be a button instead of an instruction.
    // A launcher / system tray (if present) brings the daemon back
    // up; without one, the user re-runs the daemon command.
    daemonShutdown(reason) {
      return this.post("/api/v1/daemon/shutdown", {
        confirmed_shutdown: true, reason: reason || "user_request",
      });
    },
    updateInstall() {
      return this.post(
        "/api/update/install",
        { confirmed_install: true },
        { timeoutMs: 30000 },
      );
    },
    oneHealth() { return this.get("/api/one-health"); },
    setupDeviceInvite(body) { return this.post("/api/setup/device-invite", body); },
    claimSetupDeviceInvite(body) { return this.post("/api/setup/device-invite/claim", body); },
    confirmSetupDeviceInvite(body) { return this.post("/api/setup/device-invite/confirm", body); },
    rejectSetupDeviceInvite(body) { return this.post("/api/setup/device-invite/reject", body); },
    fabric() { return this.get("/api/fabric"); },
    noRouter() { return this.get("/api/fabric/no-router"); },
    mobileReach() { return this.get("/api/fabric/mobile-reach"); },
    selfMesh() { return this.get("/api/self-mesh"); },
    selfMeshRoot(body) { return this.post("/api/self-mesh/root", body); },
    selfMeshMint(body) { return this.post("/api/self-mesh/devices/mint", body); },
    selfMeshEnroll(body) { return this.post("/api/self-mesh/devices/enroll", body); },
    selfMeshRevoke(body) { return this.post("/api/self-mesh/devices/revoke", body); },
    selfMeshDeviceSafety(body) { return this.post("/api/self-mesh/devices/safety", body); },
    selfMeshRemoteInstruct(body) { return this.post("/api/self-mesh/remote-instruct", body); },
    selfMeshInvite(body) { return this.post("/api/self-mesh/enrollment-invite", body); },
    selfMeshClaimInvite(body) { return this.post("/api/self-mesh/enrollment-invite/claim", body); },
    selfMeshPerformance() { return this.get("/api/self-mesh/performance"); },
    selfMeshAllowedRoots(body) { return this.post("/api/self-mesh/allowed-roots", body); },
    fabricPathCreate() { return this.get("/api/fabric/path-create"); },
    launchFabricPathCreate(body) { return this.post("/api/fabric/path-create/launch", body); },
    nativeFabricPathCreate(body) { return this.post("/api/fabric/path-create/native", body); },
    courierStatus() { return this.get("/api/courier/status"); },
    courierFiles() { return this.get("/api/courier/files"); },
    courierOutbox() { return this.get("/api/courier/outbox"); },
    courierRemovable() { return this.get("/api/courier/removable"); },
    courierRemovableFiles(targetId) { return this.get(`/api/courier/removable-files?target_id=${encodeURIComponent(targetId || "")}`); },
    courierExport(body) { return this.post("/api/courier/export", body); },
    courierExportFile(body) { return this.post("/api/courier/export-file", body); },
    courierCopyToRemovable(body) { return this.post("/api/courier/copy-to-removable", body); },
    courierCopyFromRemovable(body) { return this.post("/api/courier/copy-from-removable", body); },
    courierImport(body) { return this.post("/api/courier/import", body); },
    courierImportFile(body) { return this.post("/api/courier/import-file", body); },
    courierAssemble(body) { return this.post("/api/courier/assemble", body); },
    routeBootstrap() { return this.get("/api/route-bootstrap"); },
    importRouteBootstrap(token) {
      return this.post("/api/route-bootstrap/import", { token });
    },
  };

  return api;
}
