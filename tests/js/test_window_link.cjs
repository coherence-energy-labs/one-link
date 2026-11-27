"use strict";

// The owner window's link to its daemon (frontend/owner/services/window_link.js).
//
// These tests exist because of one window on 2026-11-25. The daemon restarted
// for an update; the window answered with two banners printed over each other
// ("Restoring One Link…" and "This tab's access key expired") and stayed that
// way for hours after the daemon was back, because recovery was attempted at
// most twice and nothing retried by itself. Each test below names the rule
// that would have prevented it. The service runs here with a virtual clock and
// a scripted probe: no page, no DOM, no network.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = path.resolve(__dirname, "../../frontend/owner/services/window_link.js");

function factory() {
  const context = vm.createContext({});
  new vm.Script(fs.readFileSync(source, "utf8"), { filename: "window_link.js" }).runInContext(context);
  return context.createWindowLink;
}

async function settle() {
  for (let i = 0; i < 8; i += 1) await Promise.resolve();
}

function virtualClock() {
  let now = 0;
  let seq = 0;
  const timers = new Map();
  return {
    setTimeout(fn, ms) {
      seq += 1;
      timers.set(seq, { at: now + ms, fn });
      return seq;
    },
    clearTimeout(id) { timers.delete(id); },
    now: () => now,
    pending: () => timers.size,
    // Run every timer due within the next `ms`, in order, letting promise
    // continuations finish between them (a probe's answer schedules the next).
    async advance(ms) {
      const target = now + ms;
      for (;;) {
        await settle();
        let dueId = null;
        for (const [id, timer] of timers) {
          if (timer.at <= target && (dueId === null || timer.at < timers.get(dueId).at)) dueId = id;
        }
        if (dueId === null) break;
        const timer = timers.get(dueId);
        timers.delete(dueId);
        now = timer.at;
        timer.fn();
      }
      now = target;
      await settle();
    },
  };
}

// A window link with a scripted probe. `answers` is consumed one per probe;
// when it runs out the last answer repeats.
function harness(answers, { random = () => 0.5 } = {}) {
  const clock = virtualClock();
  const seen = { probes: [], rendered: [], suspended: 0, resumed: 0, forgotten: 0 };
  let script = answers.slice();
  const link = factory()({
    probe() {
      seen.probes.push(clock.now());
      const next = script.length > 1 ? script.shift() : script[0];
      if (typeof next === "function") return next();
      return Promise.resolve(next);
    },
    forgetCredential() { seen.forgotten += 1; },
    suspend() { seen.suspended += 1; },
    resume() { seen.resumed += 1; },
    render(kind) { seen.rendered.push(kind); },
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
    random,
  });
  return { link, clock, seen, answer(next) { script = [].concat(next); } };
}

test("every collaborator is required, by name", () => {
  const create = factory();
  const complete = {
    probe() {}, forgetCredential() {}, suspend() {}, resume() {}, render() {},
    setTimeout() {}, clearTimeout() {}, random() { return 0.5; },
  };
  for (const name of Object.keys(complete)) {
    const partial = { ...complete };
    delete partial[name];
    assert.throws(() => create(partial), new RegExp(`createWindowLink needs ${name}`));
  }
  assert.equal(create(complete).session(), "ok");
});

test("a daemon that is away for fourteen minutes is waited out, and the window resumes by itself", async () => {
  // The 2026-11-25 case: a 401 arrives as the daemon goes down, then nothing
  // answers for 14 minutes. Nobody touches the window.
  const { link, clock, seen, answer } = harness(["unavailable"]);
  link.socketClosed();
  link.unauthorized();
  await clock.advance(14 * 60 * 1000);

  assert.equal(link.session(), "recovering");
  assert.equal(seen.suspended, 1);
  assert.equal(seen.resumed, 0);
  assert.equal(seen.forgotten, 0, "an unreachable daemon says nothing about the credential");
  // The old page stopped after two attempts. This one is still asking, no
  // slower than once per 30 s (+25% jitter bound) once the backoff is capped.
  assert.ok(seen.probes.length >= 25, `only ${seen.probes.length} probes in 14 minutes`);
  const gaps = seen.probes.slice(1).map((at, i) => at - seen.probes[i]);
  assert.ok(Math.max(...gaps) <= 37500, `a gap of ${Math.max(...gaps)} ms exceeds the capped backoff`);
  assert.deepEqual(gaps.slice(0, 5), [1000, 2000, 4000, 8000, 16000]);

  // The daemon is back. The next probe finds it; no click is involved.
  answer(["ok"]);
  await clock.advance(31 * 1000);
  assert.equal(link.session(), "ok");
  assert.equal(seen.resumed, 1);
  assert.equal(seen.forgotten, 0);
  link.socketGreeted();
  await clock.advance(1);
  assert.equal(link.status(), null);
  assert.equal(seen.rendered.at(-1), null);
});

test("retrying on request works at any time, not only for the first two attempts", async () => {
  const { link, clock, seen, answer } = harness(["unavailable"]);
  link.unauthorized();
  await clock.advance(5 * 60 * 1000);
  const before = seen.probes.length;
  assert.ok(before > 8);

  for (let press = 1; press <= 5; press += 1) {
    assert.equal(link.retryNow(), true);
    await settle();
    assert.equal(seen.probes.length, before + press, `press ${press} did not probe`);
    assert.equal(seen.probes.at(-1), clock.now(), "the probe was not immediate");
  }
  answer(["ok"]);
  assert.equal(link.retryNow(), true);
  await settle();
  assert.equal(link.session(), "ok");
  assert.equal(seen.resumed, 1);
  assert.equal(link.retryNow(), false, "nothing to retry once recovered");
});

test("a request to retry also resets the backoff, so the wait after it is short", async () => {
  const { link, clock, seen } = harness(["unavailable"]);
  link.unauthorized();
  await clock.advance(10 * 60 * 1000);
  link.retryNow();
  await settle();
  const pressedAt = seen.probes.at(-1);
  await clock.advance(1000);
  assert.equal(seen.probes.at(-1) - pressedAt, 1000);
});

test("one rejection does not forget the credential; two in a row do, exactly once", async () => {
  const { link, clock, seen } = harness(["rejected"]);
  link.unauthorized();
  await settle();
  assert.equal(link.session(), "recovering");
  assert.equal(seen.forgotten, 0, "a single refusal must not strand the window");
  assert.equal(seen.probes.length, 1);

  await clock.advance(1999);
  assert.equal(seen.probes.length, 1, "the confirmation is not immediate");
  await clock.advance(1);
  assert.equal(seen.probes.length, 2);
  assert.equal(link.session(), "signed_out");
  assert.equal(seen.forgotten, 1);
  assert.equal(seen.resumed, 0, "a signed-out window must not resume polling");
  assert.equal(link.status(), "signed_out");
  assert.equal(link.shouldReconnectSocket(), false);

  // Terminal: no further probes, and nothing re-arms it.
  link.unauthorized();
  assert.equal(link.retryNow(), false);
  await clock.advance(10 * 60 * 1000);
  assert.equal(seen.probes.length, 2);
  assert.equal(seen.forgotten, 1);
  assert.equal(seen.suspended, 1);
});

test("a rejection followed by no answer starts the count again", async () => {
  // refused, unreachable, refused, unreachable ... never two refusals in a row.
  const { link, clock, seen, answer } = harness(["rejected", "unavailable", "rejected", "unavailable", "rejected", "ok"]);
  link.unauthorized();
  await clock.advance(60 * 1000);
  assert.equal(seen.forgotten, 0);
  assert.equal(link.session(), "ok");
  assert.equal(seen.resumed, 1);
  assert.equal(seen.probes.length, 6);
  answer(["ok"]);
});

test("a greeted event socket recovers the session, and a late probe answer cannot undo it", async () => {
  let release;
  const slow = () => new Promise((resolve) => { release = resolve; });
  const { link, clock, seen } = harness([slow]);
  link.socketClosed();
  link.unauthorized();
  await settle();
  assert.equal(seen.probes.length, 1);

  link.socketGreeted();
  assert.equal(link.session(), "ok");
  assert.equal(seen.resumed, 1);

  release("rejected");
  await settle();
  assert.equal(clock.pending(), 0, "recovery work was scheduled for a window that has recovered");
  await clock.advance(60 * 1000);
  assert.equal(link.session(), "ok", "an answer about a state that is gone was applied");
  assert.equal(seen.forgotten, 0);
  assert.equal(seen.probes.length, 1, "probing continued after recovery");
});

test("a burst of 401s starts one recovery and keeps one probe in flight", async () => {
  let release;
  const slow = () => new Promise((resolve) => { release = resolve; });
  const { link, seen } = harness([slow]);
  for (let i = 0; i < 6; i += 1) link.unauthorized();
  link.retryNow();
  link.retryNow();
  await settle();
  assert.equal(seen.suspended, 1);
  assert.equal(seen.probes.length, 1);
  release("ok");
  await settle();
  assert.equal(seen.resumed, 1);
});

test("a probe that throws or rejects counts as no answer, never as a refusal", async () => {
  const explode = () => { throw new Error("boom"); };
  const reject = () => Promise.reject(new Error("network"));
  const { link, clock, seen } = harness([explode, reject, explode, reject, "ok"]);
  link.unauthorized();
  await clock.advance(60 * 1000);
  assert.equal(seen.forgotten, 0);
  assert.equal(link.session(), "ok");
  assert.equal(seen.probes.length, 5);
});

test("a restart that finishes inside four seconds never reaches the status line", async () => {
  const { link, clock, seen } = harness(["unavailable"]);
  link.socketClosed();
  await clock.advance(3999);
  link.socketGreeted();
  await clock.advance(60 * 1000);
  assert.deepEqual(seen.rendered.filter((kind) => kind !== null), []);
});

test("the line shows one status at a time, the most pressing one, and only when it changes", async () => {
  const { link, clock, seen } = harness(["unavailable"]);
  link.setOffline(true);
  assert.equal(link.status(), "offline");

  // Offline AND the socket is down AND a 401 arrived: still one line.
  link.socketClosed();
  link.unauthorized();
  assert.equal(link.status(), "offline", "the quiet period applies to the restoring status");
  await clock.advance(4000);
  assert.equal(link.status(), "restoring");

  // More of the same facts must not re-render the same status.
  link.socketClosed();
  link.setOffline(true);
  link.unauthorized();
  await clock.advance(30 * 1000);
  assert.deepEqual(seen.rendered, ["offline", "restoring"]);

  // Recovered while the OS is still offline: the line returns to the offline copy.
  link.socketGreeted();
  assert.equal(link.status(), "offline");
  link.setOffline(false);
  assert.equal(link.status(), null);
  assert.deepEqual(seen.rendered, ["offline", "restoring", "offline", null]);
});

test("signed out outranks everything else the line could say", async () => {
  const { link, clock, seen } = harness(["rejected"]);
  link.setOffline(true);
  link.socketClosed();
  link.unauthorized();
  await clock.advance(5 * 60 * 1000);
  assert.equal(link.status(), "signed_out");
  assert.equal(seen.rendered.at(-1), "signed_out");
  link.setOffline(false);
  link.socketClosed();
  await clock.advance(5 * 60 * 1000);
  assert.equal(link.status(), "signed_out");
  assert.equal(seen.rendered.filter((kind) => kind === "signed_out").length, 1);
});

test("a socket that authenticates after a sign-out brings the window back", async () => {
  // HTTPS windows can authenticate the socket with a cookie the page cannot
  // read. If the daemon greets it, the daemon accepted this window: believe it.
  const { link, clock, seen } = harness(["rejected"]);
  link.unauthorized();
  await clock.advance(3000);
  assert.equal(link.session(), "signed_out");
  link.socketGreeted();
  assert.equal(link.session(), "ok");
  assert.equal(seen.resumed, 1);
  assert.equal(link.status(), null);
});

test("backoff jitter stays within a quarter either side and never synchronizes", async () => {
  for (const [roll, first] of [[0, 750], [0.999999, 1249]]) {
    const { link, clock, seen } = harness(["unavailable"], { random: () => roll });
    link.unauthorized();
    await clock.advance(2000);
    assert.equal(seen.probes[1] - seen.probes[0], first);
  }
});

test("dispose stops every timer and ignores later events", async () => {
  const { link, clock, seen } = harness(["unavailable"]);
  link.socketClosed();
  link.unauthorized();
  await settle();
  link.dispose();
  assert.equal(clock.pending(), 0);
  link.socketGreeted();
  link.setOffline(true);
  link.unauthorized();
  await clock.advance(60 * 1000);
  assert.equal(seen.probes.length, 1);
  assert.equal(seen.resumed, 0);
  assert.equal(link.shouldReconnectSocket(), false);
});

// ── The page's wiring: what counts as "connected" ─────────────────────────
//
// The first version of this fix called the session recovered when the event
// socket's `open` event fired. A real daemon proved that wrong: it accepts an
// unauthenticated socket and then closes it with code 4401, so `open` fires
// for a refused credential too. The window resumed its polls, collected a
// burst of 401s, and started over about once a second until the daemon
// rate-limited it. These tests run the page's own socket modules
// (main/events.js, main/live_refresh.js) against a scripted WebSocket.

const ownerSource = path.resolve(__dirname, "../../frontend/owner");

function scope(files, globals, epilogue) {
  const names = Object.keys(globals);
  const body = files
    .map((file) => fs.readFileSync(path.join(ownerSource, file), "utf8"))
    .join("\n") + "\n" + epilogue;
  return new Function(...names, body)(...names.map((name) => globals[name]));
}

function wiredPage({ reconnectAllowed = () => true } = {}) {
  const clock = virtualClock();
  const sockets = [];
  class ScriptedWebSocket {
    constructor(url, protocols) {
      this.url = url;
      this.protocols = protocols;
      this.readyState = 0;
      this.createdAt = clock.now();
      sockets.push(this);
    }
    close() { this.readyState = 3; }
  }
  const calls = [];
  const windowLink = {
    socketGreeted() { calls.push("greeted"); },
    socketClosed() { calls.push("closed"); },
    unauthorized() { calls.push("unauthorized"); },
    retryNow() { calls.push("retry"); return false; },
    shouldReconnectSocket: () => reconnectAllowed(),
  };
  const noop = () => {};
  const page = scope(["main/live_refresh.js", "main/events.js"], {
    window: { addEventListener: noop },
    document: {
      addEventListener: noop,
      querySelector: () => null,
      getElementById: () => null,
      visibilityState: "visible",
    },
    location: { protocol: "http:", host: "127.0.0.1:7117" },
    WebSocket: ScriptedWebSocket,
    windowLink,
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
    // No jitter, so the backoff can be read exactly.
    Math: Object.assign(Object.create(Math), { random: () => 0.5 }),
    Date: { now: () => clock.now() },
    _ownerBearerToken: () => "bearer",
    api: { get: async () => ({}) },
    refreshPeers: noop,
    refreshTransfers: noop,
    refreshStatus: noop,
    sessionStorage: { getItem: () => null, setItem: noop },
    PAGE_BUILT_FOR: "test",
    PAGE_SOURCE_FINGERPRINT: "__ONE_LINK_SOURCE_FINGERPRINT__",
    toast: noop,
    console,
  }, "return { connectWS, LiveRefresh };");
  return { page, clock, sockets, calls };
}

// Let the page's reconnect timer fire and report how long it waited.
async function nextSocketDelay(clock, sockets) {
  const count = sockets.length;
  const from = clock.now();
  await clock.advance(120 * 1000);
  assert.equal(sockets.length, count + 1, "the page did not reconnect exactly once");
  return sockets.at(-1).createdAt - from;
}

test("a socket the daemon opens and then refuses is not a connection, and it backs off", async () => {
  const { page, clock, sockets, calls } = wiredPage();
  page.connectWS();
  assert.equal(sockets[0].url, "ws://127.0.0.1:7117/api/events");
  assert.deepEqual(sockets[0].protocols, ["one-link.owner.v1", "one-link.bearer.bearer"]);

  const delays = [];
  for (let round = 0; round < 5; round += 1) {
    const ws = sockets.at(-1);
    // Nothing may be waiting on `open`: for a refused credential the browser
    // fires it just before the 4401 close.
    assert.equal(ws.onopen, undefined, "something still treats the open event as a connection");
    ws.onclose({ code: 4401 });
    delays.push(await nextSocketDelay(clock, sockets));
  }
  assert.deepEqual(delays, [1000, 2000, 4000, 8000, 16000], "a refused socket reset the backoff");
  assert.equal(calls.includes("greeted"), false);
  assert.deepEqual(calls.slice(0, 2), ["closed", "unauthorized"], "a 4401 close must start a credential check");
  assert.equal(calls.filter((call) => call === "unauthorized").length, 5);
});

test("the daemon's greeting is the connection: it reports once and resets the backoff", async () => {
  const { page, clock, sockets, calls } = wiredPage();
  page.connectWS();
  sockets[0].onclose({ code: 1006 });
  assert.equal(await nextSocketDelay(clock, sockets), 1000);
  sockets[1].onclose({ code: 1006 });
  assert.equal(await nextSocketDelay(clock, sockets), 2000);
  assert.equal(calls.includes("unauthorized"), false, "an ordinary close is not a refusal");

  const ws = sockets[2];
  ws.onmessage({ data: "not json" });
  ws.onmessage({ data: JSON.stringify({ type: "something_else" }) });
  assert.equal(calls.includes("greeted"), false, "only the greeting counts");
  ws.onmessage({ data: JSON.stringify({ type: "hello", me: { short_id: "abc" } }) });
  assert.equal(calls.filter((call) => call === "greeted").length, 1);

  ws.onclose({ code: 1006 });
  assert.equal(await nextSocketDelay(clock, sockets), 1000, "the greeting did not reset the backoff");
});

test("a signed-out window stops reconnecting, including a reconnect already scheduled", async () => {
  let allowed = true;
  const { page, clock, sockets } = wiredPage({ reconnectAllowed: () => allowed });
  page.connectWS();
  sockets[0].onclose({ code: 4401 });  // schedules a reconnect in 1 s
  allowed = false;                      // ...and the window is signed out before it fires
  await clock.advance(10 * 60 * 1000);
  assert.equal(sockets.length, 1, "a signed-out window presented itself to the daemon again");
  page.LiveRefresh.forceReconnectNow();
  sockets[0].onclose({ code: 4401 });
  await clock.advance(10 * 60 * 1000);
  assert.equal(sockets.length, 1);

  // Signed back in (a new credential arrived): reconnecting works again.
  allowed = true;
  page.LiveRefresh.forceReconnectNow();
  assert.equal(sockets.length, 2);
});
