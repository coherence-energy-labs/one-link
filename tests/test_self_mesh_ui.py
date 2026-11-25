from pathlib import Path


def test_activity_panel_contains_self_mesh_surface():
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert 'id="self-mesh-kit"' in src
    assert 'id="self-mesh-devices"' in src
    assert 'id="self-mesh-device-select"' in src
    assert 'id="self-mesh-perf"' in src
    assert 'id="btn-self-mesh-root"' in src
    assert 'id="btn-self-mesh-mint"' in src
    assert 'id="btn-self-mesh-invite"' in src
    assert 'id="btn-self-mesh-claim"' in src
    assert 'id="btn-self-mesh-best"' in src
    assert 'id="btn-self-mesh-freeze"' in src
    assert 'id="btn-self-mesh-recover"' in src
    assert 'id="btn-self-mesh-trust-root"' in src
    assert 'id="btn-self-mesh-send"' in src
    assert 'id="self-mesh-advanced"' in src
    assert "Advanced device setup" in src
    assert 'id="self-mesh-invite-qr"' in src
    assert "renderSelfMesh()" in src
    assert "refreshSelfMesh()" in src


def test_self_mesh_ui_fetches_and_listens_for_daemon_events():
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert 'selfMesh() { return this.get("/api/self-mesh"); }' in src
    assert 'selfMeshRoot(body) { return this.post("/api/self-mesh/root", body); }' in src
    assert 'selfMeshMint(body) { return this.post("/api/self-mesh/devices/mint", body); }' in src
    assert 'selfMeshDeviceSafety(body) { return this.post("/api/self-mesh/devices/safety", body); }' in src
    assert 'selfMeshRemoteInstruct(body) { return this.post("/api/self-mesh/remote-instruct", body); }' in src
    assert 'selfMeshInvite(body) { return this.post("/api/self-mesh/enrollment-invite", body); }' in src
    assert 'selfMeshClaimInvite(body) { return this.post("/api/self-mesh/enrollment-invite/claim", body); }' in src
    assert 'selfMeshPerformance() { return this.get("/api/self-mesh/performance"); }' in src
    assert 'selfMeshAllowedRoots(body) { return this.post("/api/self-mesh/allowed-roots", body); }' in src
    assert 'm.type === "self_mesh_changed"' in src
    assert "identityStore.replaceSelfMesh(await api.selfMesh())" in src
    assert "mesh.timeline" in src
    assert "performance_observations" in src
    assert "performance_budgets" in src


def test_self_mesh_ui_has_enrollment_and_remote_instruction_handlers():
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert "function createSelfMeshRoot()" in src
    assert "function mintSelfMeshDeviceCert()" in src
    assert "function enrollSelfMeshCert()" in src
    assert "function revokeSelfMeshDevice()" in src
    assert "function freezeSelfMeshDevice()" in src
    assert "function recoverSelfMeshDevice()" in src
    assert "function createSelfMeshInvite()" in src
    assert "function chooseBestSelfMeshDevice()" in src
    assert "function selfMeshActionLabel(action)" in src
    assert "function sendSelfMeshInstruction(action)" in src
    assert 'sendSelfMeshInstruction("pull_file_manifest")' in src
    assert 'sendSelfMeshInstruction("send_file_from_device")' in src


def test_peer_shell_has_phone_first_self_mesh_enrollment():
    src = Path("src/one_link/web/peer.html").read_text(encoding="utf-8")
    assert 'id="selfmesh-enroll-card"' in src
    assert 'id="btn-selfmesh-claim"' in src
    assert "_detectSelfMeshInviteQuery()" in src
    assert "_runSelfMeshInviteFlow" in src
    assert "/api/v1/self-mesh/enrollment-invite/preview" in src
    assert "ol_peer.self_mesh_cert.v1" in src


def test_peer_shell_can_claim_one_setup_device_invite():
    src = Path("src/one_link/web/peer.html").read_text(encoding="utf-8")
    assert "_detectSetupDeviceInviteQuery()" in src
    assert "_runSetupDeviceInviteFlow" in src
    assert "setup_device_invite" in src
    assert '"/api/setup/device-invite/claim"' in src
    assert "device_pub_b64: rec.public_key_b64u" in src
    assert "cert_b64: body.cert_b64 ||" in src
    assert "pending: !!body.pending" in src
    assert "await _validateSetupClaim(query, rec, body)" in src
    assert "trust_phrase: verifiedSas.phrase" in src
    assert "sas_version: SETUP_SAS_VERSION" in src
    assert "Check all five words on the other device" in src
