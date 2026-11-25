"use strict";

// These services execute without the owner page, its mutable closure, DOM,
// network, or timers. A missing injected dependency therefore fails here.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const root = path.resolve(__dirname, "../..");
const source = path.join(root, "src/one_link/web/owner_ui");
const manifest = JSON.parse(fs.readFileSync(path.join(source, "manifest.json"), "utf8"));

function service(name, globals = {}) {
  const context = vm.createContext(globals);
  const body = fs.readFileSync(path.join(source, "services", name + ".js"), "utf8");
  new vm.Script(body, { filename: name + ".js" }).runInContext(context);
  return context;
}

test("every canonical module and both shipped closures parse independently", () => {
  for (const group of manifest.groups) {
    for (const module of group.modules) {
      const body = fs.readFileSync(path.join(source, module.path), "utf8");
      new vm.Script("(function () {\n" + body + "\n})();", { filename: module.path });
    }
  }
  const html = fs.readFileSync(path.join(source, "../index.html"), "utf8");
  const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.equal(blocks.length, 2);
  blocks.forEach((match, index) => new vm.Script(match[1], { filename: `owner-inline-${index}.js` }));
});

test("owner, call, and media instances never share mutable collections", async () => {
  const owner = service("owner_state");
  const a = owner.createOwnerState();
  const b = owner.createOwnerState();
  a.peers.set("alice", {});
  a.staged.push({ id: 1 });
  a.pairing.peerFp = "alice";
  assert.equal(b.peers.size, 0);
  assert.equal(b.staged.length, 0);
  assert.equal(b.pairing.peerFp, null);

  const calls = service("call_state");
  const c = calls.createCallState();
  const d = calls.createCallState();
  c.acceptedCallIds.add("call-1");
  c.pendingIceCandidates.push({ candidate: "x" });
  assert.equal(d.acceptedCallIds.size, 0);
  assert.equal(d.pendingIceCandidates.length, 0);

  const media = service("media_state");
  const e = media.createCallMediaState();
  const f = media.createCallMediaState();
  e.localCandidateAddresses.push("127.0.0.1");
  assert.equal(f.localCandidateAddresses.length, 0);
  assert.notEqual(e.iceSignalChain, f.iceSignalChain);
  await Promise.all([e.iceSignalChain, f.iceSignalChain]);
});

test("formatting consumes injected DOM and current settings", () => {
  class Clock extends Date {
    toLocaleTimeString(_locale, options) { return JSON.stringify(options); }
  }
  const factory = service("formatting", { Date: Clock }).createOwnerFormatting;
  let settings = {};
  const fmt = factory({
    document: {
      querySelector: (selector) => ({ selector }),
      createElement: (tag) => ({ tag }),
    },
    getSettings: () => settings,
  });
  assert.equal(fmt.fmtBytes(1024), "1.0 KB");
  assert.equal(fmt.fmtRate(2048), "2.0 KB/s");
  assert.equal(fmt.fmtEta(185000, 1000), "3m 05s");
  assert.equal(fmt.fmtTime(0).includes("second"), false);
  settings = { show_message_seconds: true };
  assert.equal(fmt.fmtTime(0).includes('"second":"2-digit"'), true);
  assert.equal(fmt.$("#input").selector, "#input");
  assert.equal(fmt.el("span", "note", "hello").textContent, "hello");
  assert.equal(fmt.displayFileName("1779676087532_0d1e262c1c60b45f_paper.pdf"), "paper.pdf");
});

class TestFormData {
  constructor() { this.values = new Map(); }
  append(key, value) { this.values.set(key, value); }
  get(key) { return this.values.get(key); }
}

function apiClient(fetch, overrides = {}) {
  let serial = 0;
  return service("api_client").createOwnerApiClient({
    fetch,
    _maybe401: () => {},
    _apiError: (body, status) => new Error(`${status}: ${body.error || "failed"}`),
    _newClientMsgId: () => `intent-${++serial}`,
    AbortController,
    FormData: TestFormData,
    Blob,
    setTimeout,
    clearTimeout,
    ...overrides,
  });
}

function response(value = {}) {
  return { ok: true, status: 200, json: async () => value };
}

test("HTTP coalescing covers only concurrent reads and survives a rejected request", async () => {
  let calls = 0;
  let resolve;
  let reject;
  const api = apiClient(() => {
    calls += 1;
    return new Promise((yes, no) => { resolve = yes; reject = no; });
  });
  const a = api.get("/api/status");
  const b = api.get("/api/status");
  assert.equal(calls, 1);
  resolve(response({ epoch: 1 }));
  assert.equal((await a).epoch, 1);
  assert.equal((await b).epoch, 1);
  const failed = api.get("/api/status");
  reject(new Error("connection lost"));
  await assert.rejects(failed, /connection lost/);
  const retry = api.get("/api/status");
  assert.equal(calls, 3);
  resolve(response({ epoch: 2 }));
  assert.equal((await retry).epoch, 2);
});

test("HTTP error callbacks and timeout cleanup cross the service interface", async () => {
  const statuses = [];
  let cleared = 0;
  const api = apiClient(async () => ({
    ok: false, status: 401, json: async () => ({ error: "session expired" }),
  }), {
    _maybe401: (status) => statuses.push(status),
    setTimeout: () => 123,
    clearTimeout: (handle) => { assert.equal(handle, 123); cleared += 1; },
  });
  await assert.rejects(api.get("/api/status", { timeoutMs: 100 }), /401: session expired/);
  await assert.rejects(api.post("/api/send", {}, { timeoutMs: 100 }), /401: session expired/);
  assert.deepEqual(statuses, [401, 401]);
  assert.equal(cleared, 2);
});

test("file retries preserve one immutable intent while concurrent calls coalesce", async () => {
  const requests = [];
  let resolve;
  let reject;
  const api = apiClient((_url, request) => {
    requests.push(request.body);
    return new Promise((yes, no) => { resolve = yes; reject = no; });
  });
  const file = { name: "proof.bin", size: 32 };
  const a = api.upload("alice", file, { relPath: "folder/proof.bin" });
  const b = api.upload("alice", file, { relPath: "folder/proof.bin" });
  assert.equal(requests.length, 1);
  reject(new Error("response lost"));
  await Promise.all([assert.rejects(a, /response lost/), assert.rejects(b, /response lost/)]);
  const retry = api.upload("alice", file, { relPath: "folder/proof.bin" });
  assert.equal(requests.length, 2);
  assert.equal(requests[1].get("client_delivery_id"), requests[0].get("client_delivery_id"));
  resolve(response({ confirmed: true }));
  assert.equal((await retry).confirmed, true);
  const differentPeer = api.upload("bob", file, { relPath: "folder/proof.bin" });
  assert.notEqual(requests[2].get("client_delivery_id"), requests[0].get("client_delivery_id"));
  resolve(response());
  await differentPeer;
});

function healthService() {
  const callUI = service("call_state").createCallState();
  const media = service("media_state").createCallMediaState();
  const changes = [];
  const health = service("call_health").createCallHealth({
    callUI, media,
    setReconnectState: (on) => changes.push(["reconnecting", on]),
    updateCallQuality: (level) => changes.push(["quality", level]),
    targetMediaProfile: (level) => ({ maxBitrate: 800000 / (level + 1), scale: level + 1 }),
    applyCaptureProfileForTau: async (level) => changes.push(["capture", level]),
    updateOneChip: () => {},
    addOneCallEvent: () => {},
    reportCallEvent: (event) => changes.push(["event", event]),
  });
  return { health, callUI, media, changes };
}

const liveMetrics = {
  has_local_description: true,
  has_remote_description: true,
  ice_connection_state: "connected",
  connection_state: "connected",
  signaling_state: "stable",
  remote_live_audio_tracks: 1,
  inbound_audio_packets: 10,
  smoothed_rtt_ms: 50,
  loss_rate: 0,
};

test("call health distinguishes connecting, missing media, and transport recovery", () => {
  const { health, media } = healthService();
  assert.equal(health.classifyCallQuality(liveMetrics), "good");
  assert.equal(health.classifyCallQuality({ ...liveMetrics, has_remote_description: false }), "connecting");
  const missing = { ...liveMetrics, remote_live_audio_tracks: 0, inbound_audio_packets: 0 };
  assert.equal(health.classifyMediaHealth(missing).state, "remote_media_missing");
  assert.equal(health.classifyCallQuality(missing), "connecting");
  media.reconnecting = true;
  assert.equal(health.classifyCallQuality(liveMetrics), "reconnecting");
});

test("call health state and adaptive actions stay inside the injected call instance", async () => {
  const { health, callUI, media, changes } = healthService();
  const untouched = healthService();
  for (let i = 0; i < 3; i++) health.applyCallQualityHysteresis("bad", "high loss");
  assert.equal(callUI.qualityBadTicks, 3);
  assert.equal(untouched.callUI.qualityBadTicks, 0);
  assert.deepEqual(changes.at(-1), ["quality", "bad"]);
  let parameters;
  media.pc = { getSenders: () => [{
    track: { kind: "video" },
    getParameters: () => ({}),
    setParameters: async (value) => { parameters = value; },
  }] };
  await health.tuneOutboundMediaForTau({ ...liveMetrics, ice_connection_state: "failed" });
  assert.equal(callUI.adaptationLevel, 3);
  assert.equal(parameters.encodings[0].maxBitrate, 200000);
  assert.equal(parameters.encodings[0].scaleResolutionDownBy, 4);
  assert(changes.some(([kind, value]) => kind === "event" && value === "tau_media_adapted"));
  assert.equal(untouched.callUI.adaptationLevel, 0);
});
