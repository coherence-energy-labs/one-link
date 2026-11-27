  async function refreshSelfMesh({ refreshHealth = true } = {}) {
    try {
      identityStore.replaceSelfMesh(await api.selfMesh());
      renderSelfMesh();
      if (refreshHealth) await refreshOneHealth();
    } catch (_e) {
      renderSelfMesh();
    }
  }
  function _selectedSelfMeshDevice() {
    const mesh = state.selfMesh || {};
    const select = $("#self-mesh-device-select");
    const devicePub = select?.value || "";
    return (mesh.devices || []).find(d => d.device_pub_b64 === devicePub) || null;
  }
  async function createSelfMeshRoot() {
    const seed = ($("#self-mesh-root-seed")?.value || "").trim();
    const label = ($("#self-mesh-device-label")?.value || "").trim();
    try {
      const res = await api.selfMeshRoot({
        label: "My devices",
        root_seed_b64: seed || undefined,
        device_label: label || undefined,
      });
      if (res?.local_cert_b64 && $("#self-mesh-cert")) {
        $("#self-mesh-cert").value = res.local_cert_b64;
      }
      if (seed && $("#self-mesh-root-seed")) $("#self-mesh-root-seed").value = "";
      toast(seed ? "Personal mesh restored" : "Personal mesh ready", "good");
      await refreshSelfMesh();
    } catch (e) {
      toast(`Root setup failed: ${errorToastBody(e)}`, "bad", 6000);
    }
  }
  function selfMeshActionLabel(action) {
    return {
      pull_file_manifest: "file list",
      send_file_from_device: "file send",
    }[action] || "request";
  }
  async function mintSelfMeshDeviceCert() {
    const d = _selectedSelfMeshDevice();
    const devicePub = ($("#self-mesh-device-pub")?.value || "").trim();
    const label = ($("#self-mesh-device-label")?.value || "").trim();
    if (!d?.root_pub_b64) return toast("Set up your devices first.", "info");
    if (!devicePub) return toast("Paste the new device public key first.", "info");
    try {
      const res = await api.selfMeshMint({
        root_pub_b64: d.root_pub_b64,
        device_pub_b64: devicePub,
        label: label || "Trusted device",
        device_kind: "personal-device",
      });
      if ($("#self-mesh-cert")) $("#self-mesh-cert").value = res.cert_b64 || "";
      await copyToClipboard(res.cert_b64 || "", "device cert");
      toast("Device certificate copied", "good");
      await refreshSelfMesh();
    } catch (e) {
      toast(`Certificate didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }
  async function enrollSelfMeshCert() {
    const cert = ($("#self-mesh-cert")?.value || "").trim();
    if (!cert) return toast("Paste a device cert first.", "info");
    try {
      await api.selfMeshEnroll({ cert_b64: cert, trusted: true });
      $("#self-mesh-cert").value = "";
      toast("Device enrolled", "good");
      await refreshSelfMesh();
    } catch (e) {
      toast(`Enroll didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }
  async function revokeSelfMeshDevice() {
    const d = _selectedSelfMeshDevice();
    if (!d) return toast("Choose a device first.", "info");
    try {
      const res = await api.selfMeshDeviceSafety({
        root_pub_b64: d.root_pub_b64,
        device_pub_b64: d.device_pub_b64,
        state: "revoked",
        proofs: ["already_frozen"],
        reason: "user requested hard revoke",
      });
      if (!res?.ok) return toast(res?.decision?.detail || "Couldn't remove this device. Try again from a trusted device you've verified in person.", "warn", 8000);
      toast("Device hard revoked", "warn");
      await refreshSelfMesh();
    } catch (e) {
      toast(`Revoke didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }
  async function setSelfMeshDeviceSafety(safetyState, proofs, reason, label) {
    const d = _selectedSelfMeshDevice();
    if (!d) return toast("Choose a device first.", "info");
    try {
      const res = await api.selfMeshDeviceSafety({
        root_pub_b64: d.root_pub_b64,
        device_pub_b64: d.device_pub_b64,
        state: safetyState,
        proofs,
        reason,
      });
      if (!res?.ok) return toast(res?.decision?.detail || "Couldn't change safety status. Try again from a trusted device you've verified in person.", "warn", 8000);
      toast(label, safetyState === "trusted" ? "good" : "warn", 7000);
      await refreshSelfMesh();
    } catch (e) {
      toast(`Guardian didn't work: ${errorToastBody(e)}`, "bad", 7000);
    }
  }
  function freezeSelfMeshDevice() {
    return setSelfMeshDeviceSafety(
      "frozen",
      ["recent_unlock"],
      "user froze device from Safety Center",
      "Device frozen. It cannot route, pull files, or run remote commands.",
    );
  }
  function recoverSelfMeshDevice() {
    return setSelfMeshDeviceSafety(
      "trusted",
      ["recent_unlock"],
      "user recovered device",
      "Device recovered and trusted again.",
    );
  }
  function chooseBestSelfMeshDevice() {
    const mesh = state.selfMesh || {};
    const select = $("#self-mesh-device-select");
    const devices = Array.isArray(mesh.devices) ? mesh.devices : [];
    if (!select || devices.length === 0) return toast("No trusted device yet.", "info");
    const scored = devices
      .filter(d => d.device_pub_b64 && !d.revoked)
      .map(d => {
        const p = _selfMeshPresenceFor(d);
        const latency = Number(p?.latency_ms ?? 999999);
        const awake = p?.state === "awake" ? 1000 : 0;
        const local = d.local ? 100 : 0;
        const trusted = d.trusted ? 50 : 0;
        const recent = Number(p?.updated_ms || d.updated_ms || 0) / 100000000000;
        return { d, score: awake + local + trusted + recent - Math.min(latency, 999999) / 1000 };
      })
      .sort((a, b) => b.score - a.score);
    const best = scored[0]?.d || null;
    if (!best) return toast("No usable device to choose yet.", "info");
    select.value = best.device_pub_b64;
    toast(`Using ${best.label || best.device_kind || "best device"}`, "good", 2500);
    renderSelfMesh();
  }
  async function createSelfMeshInvite() {
    const d = _selectedSelfMeshDevice();
    if (!d) return toast("Choose a device first.", "info");
    try {
      const invite = await api.selfMeshInvite({
        root_pub_b64: d.root_pub_b64,
        device_pub_b64: d.device_pub_b64,
        label: d.label || d.device_kind || "One Link device",
      });
      const qr = $("#self-mesh-invite-qr");
      if (qr && invite.qr_url) {
        qr.src = `${invite.qr_url}&t=${Date.now()}`;
        qr.style.display = "block";
      }
      await copyToClipboard(invite.deep_link || invite.token, "self-mesh invite");
      toast("Invite ready", "good");
      await refreshSelfMesh();
    } catch (e) {
      toast(`Invite didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }
  async function claimSelfMeshInvite() {
    const token = ($("#self-mesh-cert")?.value || "").trim();
    if (!token) return toast("Paste an invite token first.", "info");
    try {
      await api.selfMeshClaimInvite({
        token,
        label: state.me?.hostname || "This device",
        device_kind: "local-device",
      });
      $("#self-mesh-cert").value = "";
      toast("Invite claimed", "good");
      await refreshSelfMesh();
    } catch (e) {
      toast(`Claim didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }
  async function sendSelfMeshInstruction(action) {
    const d = _selectedSelfMeshDevice();
    const path = ($("#self-mesh-path")?.value || "").trim();
    const peer = ($("#self-mesh-peer")?.value || "").trim();
    if (!d) return toast("Choose a device first.", "info");
    if (!path) return toast("Enter an allowed file path.", "info");
    if (!peer) return toast("Enter a peer or device target.", "info");
    const scope = { path };
    if (action === "send_file_from_device") {
      scope.recipient_fp = peer;
    }
    try {
      await api.selfMeshRemoteInstruct({
        root_pub_b64: d.root_pub_b64,
        target_device_pub_b64: d.device_pub_b64,
        peer,
        action,
        scope,
      });
      toast(action === "pull_file_manifest" ? "File list requested" : "File send queued", "good");
      await refreshSelfMesh();
    } catch (e) {
      toast(`Request didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }
  async function trustSelfMeshFolder() {
    const path = ($("#self-mesh-path")?.value || "").trim();
    if (!path) return toast("Enter a folder path to trust.", "info");
    const current = Array.isArray(state.selfMesh?.allowed_roots)
      ? state.selfMesh.allowed_roots
      : [];
    try {
      await api.selfMeshAllowedRoots({ roots: Array.from(new Set([...current, path])) });
      toast("Trusted folder added", "good");
      await refreshSelfMesh();
    } catch (e) {
      toast(`Trust update failed: ${errorToastBody(e)}`, "bad", 6000);
    }
  }
