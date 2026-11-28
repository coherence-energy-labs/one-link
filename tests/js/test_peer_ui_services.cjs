"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const root = path.resolve(__dirname, "../..");
const source = path.join(root, "frontend/peer");
const manifest = JSON.parse(fs.readFileSync(path.join(source, "manifest.json"), "utf8"));

function service(name) {
  const context = vm.createContext({});
  const body = fs.readFileSync(path.join(source, "services", name + ".js"), "utf8");
  new vm.Script('"use strict";\n' + body, { filename: name + ".js" }).runInContext(context);
  return context;
}

const plain = (value) => JSON.parse(JSON.stringify(value));

test("peer modules and the actual offline page parse without loading feature state", () => {
  for (const module of manifest.groups[0].modules) {
    const body = fs.readFileSync(path.join(source, module.path), "utf8");
    new vm.Script('(function () {\n"use strict";\n' + body + "\n})();", { filename: module.path });
  }
  const html = fs.readFileSync(path.join(root, "src/one_link/web/peer.html"), "utf8");
  const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.equal(blocks.length, 1);
  new vm.Script(blocks[0][1], { filename: "shipped-peer.js" });
});

test("encoding preserves exact bytes and URL-safe presentation", () => {
  const encoding = service("encoding").createPeerEncoding({ btoa, atob });
  const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
  const encoded = encoding.bytesToB64Url(bytes);
  assert(!/[+/=]/.test(encoded));
  assert.deepEqual(Array.from(encoding.b64UrlToBytes(encoded)), Array.from(bytes));
  assert.equal(encoding.bytesToHex(Uint8Array.of(0, 15, 16, 255)), "000f10ff");
});

test("peer identity state is fresh and progress belongs to the injected instance", () => {
  const makeState = service("state").createPeerState;
  const makeIdentity = service("identity").createPeerIdentity;
  const first = makeState();
  const second = makeState();
  const firstIdentity = makeIdentity();
  const secondIdentity = makeIdentity();
  firstIdentity.unlock({ fingerprint: "fixture" }, { v: 2 });
  assert.equal(firstIdentity.rec().fingerprint, "fixture");
  assert.equal(secondIdentity.rec(), null);
  assert.equal(secondIdentity.envelope(), null);
  assert.notEqual(first, second);
  let tick = 0;
  const progress = service("progress").createPeerProgress({
    state: first, performance: { now: () => tick++ * 10 },
  });
  const mark = progress._pairingProgress();
  for (let i = 0; i < 40; i++) mark("gathering_ice", {
    connectionState: "connecting", iceConnectionState: "checking", iceGatheringState: "gathering",
  }, { readyState: "connecting" });
  assert.equal(first.autopair_diagnostics.history.length, 32);
  assert.equal(first.autopair_diagnostics.elapsed_ms, 400);
  assert.equal(second.autopair_diagnostics, undefined);
  const previous = first.autopair_diagnostics;
  progress._pairingProgress();
  assert.notEqual(first.autopair_diagnostics, previous);
  assert.equal(first.autopair_diagnostics.history.length, 0);
});

function configClient(fetch, overrides = {}) {
  return service("ice_config").createPeerIceConfig({
    fetch, AbortController, setTimeout, clearTimeout, ...overrides,
  });
}

test("public ICE config retains STUN and explicitly enabled local assistance", async () => {
  let cleared = false;
  const client = configClient(async (url, options) => {
    assert.equal(url, "/api/v1/peer-rtc/ice-config");
    assert.equal(options.cache, "no-store");
    assert.equal(options.credentials, "same-origin");
    return { ok: true, json: async () => ({
      iceServers: [{ urls: "stun:example.test:3478" }, { urls: "turn:example.test:3478", credential: "fixture" }],
      local_address_discovery: {
        enabled: true, external: false, scope: "same-device-or-lan",
        candidate_addresses: ["192.0.2.10", "192.0.2.10", "192.0.2.11"],
      },
    }) };
  }, {
    setTimeout: (_callback, duration) => { assert.equal(duration, 8000); return 42; },
    clearTimeout: (handle) => { assert.equal(handle, 42); cleared = true; },
  });
  assert.deepEqual(plain(await client.loadPublicIceConfig()), {
    iceServers: [{ urls: "stun:example.test:3478" }],
    localCandidateAddresses: ["192.0.2.10", "192.0.2.11"],
  });
  assert(cleared);
});

test("public ICE timeout aborts the request and preserves host-only fallback", async () => {
  let deadline;
  let cleared = false;
  let signal;
  const client = configClient(async (_url, options) => {
    signal = options.signal;
    return new Promise((_resolve, reject) => signal.addEventListener("abort", () => reject(new Error("aborted"))));
  }, {
    setTimeout: (callback) => { deadline = callback; return 7; },
    clearTimeout: (handle) => { assert.equal(handle, 7); cleared = true; },
  });
  const pending = client.loadPublicIceConfig();
  deadline();
  assert.deepEqual(plain(await pending), { iceServers: [], localCandidateAddresses: [] });
  assert(signal.aborted);
  assert(cleared);
});

test("disabled local assistance does not contribute candidate addresses", async () => {
  const client = configClient(async () => ({ ok: true, json: async () => ({
    iceServers: [],
    local_address_discovery: {
      enabled: false, external: false, scope: "same-device-or-lan", candidate_addresses: ["192.0.2.10"],
    },
  }) }));
  assert.deepEqual(plain(await client.loadPublicIceConfig()), { iceServers: [], localCandidateAddresses: [] });
});

// Execute the real canonical UI module, with deterministic clock, deferred
// network results and lifecycle events. No browser clock/event-loop timing
// assumptions are needed to reach the races.
function rendezvousLifecycleFixture() {
  const handlers = new Map();
  const timers = new Map();
  const requests = [];
  const statuses = [];
  let nextId = 1;
  let now = 100000;
  class ClockDate extends Date {
    constructor(...args) { super(...(args.length ? args : [now])); }
    static now() { return now; }
  }
  const context = vm.createContext({
    Date: ClockDate,
    RDZ_REFRESH_MARGIN_MS: 30000,
    window: { addEventListener: (name, fn) => handlers.set(name, fn) },
    $: () => null,
    text: (_node, status) => statuses.push(status),
    _normalizeRdzUrl: (url) => url,
    setTimeout: (fn, delay) => {
      const id = nextId++;
      timers.set(id, { fn, delay });
      return id;
    },
    clearTimeout: (id) => timers.delete(id),
    registerWith: (url) => new Promise((resolve, reject) => {
      requests.push({ url, resolve, reject });
    }),
  });
  const sourceText = fs.readFileSync(path.join(source, "ui/rendezvous.js"), "utf8");
  new vm.Script(sourceText + "\n;globalThis.fixture = { start: _startRdzRefresh, cancel: _cancelRdzRefresh };").runInContext(context);
  const ack = { expires_at_ms: 60000, server_time_ms: 0 };
  const start = (url = "https://fixture.invalid") => context.fixture.start(ack, url);
  const event = (name, persisted = true) => handlers.get(name)({ persisted });
  const fire = () => {
    assert.equal(timers.size, 1);
    const [id, timer] = timers.entries().next().value;
    timers.delete(id);
    now += timer.delay;
    return timer.fn();
  };
  return { timers, requests, statuses, ack, start, event, fire, cancel: context.fixture.cancel };
}

test("rendezvous: in-flight completion cannot re-arm a hidden page", async () => {
  const f = rendezvousLifecycleFixture();
  f.start();
  const pending = f.fire();
  assert.equal(f.requests.length, 1);
  f.event("pagehide");
  f.requests[0].resolve(f.ack);
  await pending;
  assert.equal(f.timers.size, 0);
  f.event("pageshow");
  f.event("pageshow");
  assert.equal(f.timers.size, 1);
});

test("rendezvous: restored page cannot schedule overlapping refreshes", async () => {
  const f = rendezvousLifecycleFixture();
  f.start();
  const pending = f.fire();
  f.event("pagehide");
  f.event("pageshow");
  f.event("pageshow");
  assert.equal(f.timers.size, 0);
  f.requests[0].reject(new Error("offline"));
  await pending;
  assert.equal(f.timers.size, 1);
  assert.equal([...f.timers.values()][0].delay, 4000);
});

test("rendezvous: stale completion cannot modify replacement registration", async () => {
  const f = rendezvousLifecycleFixture();
  f.start("https://old.invalid");
  const pending = f.fire();
  f.start("https://new.invalid");
  const newTimer = [...f.timers.keys()][0];
  f.requests[0].resolve(f.ack);
  await pending;
  assert.deepEqual([...f.timers.keys()], [newTimer]);
  assert.deepEqual(f.statuses, []);
});

test("rendezvous: registration finishing during a hidden page stays paused", () => {
  const f = rendezvousLifecycleFixture();
  f.event("pagehide");
  f.start();
  assert.equal(f.timers.size, 0);
  f.event("pageshow");
  assert.equal(f.timers.size, 1);
});

test("rendezvous: queued obsolete timer cannot initiate a request", async () => {
  const f = rendezvousLifecycleFixture();
  f.start();
  const obsolete = [...f.timers.values()][0];
  f.event("pageshow");
  await obsolete.fn();
  assert.equal(f.requests.length, 0);
  assert.equal(f.timers.size, 1);
});
