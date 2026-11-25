"use strict";

// MNT-03 behavioural contracts for the owner page's feature state owners.
// Each owner runs here without the page, DOM, network or real timers, from
// the canonical source modules the builder ships. Where an older source-text
// test pinned a raw write (for example `state.transferRates.delete(`), the
// test below pins the behaviour that write had through the owner's API.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const root = path.resolve(__dirname, "../..");
const owner = path.join(root, "frontend/owner");
const read = (rel) => fs.readFileSync(path.join(owner, rel), "utf8");

// Run source modules inside one private function scope, as the builder's
// services scope does, in sloppy mode like the owner and call closures
// (where a write to a frozen object would fail silently). Only the named
// `globals` are injected. Evaluated in this realm so errors and arrays
// compare as ordinary values.
function scope(files, globals, epilogue) {
  const names = Object.keys(globals);
  const body = files.map(read).join("\n") + "\n" + epilogue;
  return new Function(...names, body)(...names.map((name) => globals[name]));
}
function load(files, globals = {}) {
  const factories = [...files.map(read).join("\n").matchAll(/^function (create[A-Za-z]+)\(/gm)].map((m) => m[1]);
  return scope(files, globals, `return { ${factories.join(", ")} };`);
}

// ── State publisher ─────────────────────────────────────────────────────

test("published fields read the owner's live value and refuse a raw write by name", () => {
  const { createStatePublisher } = load(["services/state_publisher.js"]);
  const state = { peers: new Map() };
  const publisher = createStatePublisher(state);
  let current = [1];
  publisher.publish("transferStore", { transfers: () => current });
  assert.equal(state.transfers, current);
  current = [2];
  assert.equal(state.transfers, current, "the accessor reads the owner, not a copy");
  assert.throws(() => { state.transfers = []; }, (e) => e instanceof TypeError && /transferStore/.test(e.message));
  assert.deepEqual(Object.keys(state), ["peers", "transfers"]);
  assert.equal(publisher.ownerOf("transfers"), "transferStore");
  assert.throws(() => publisher.publish("other", { transfers: () => 1 }), /already has an owner/);
  assert.throws(() => publisher.publish("other", { peers: () => 1 }), /already has an owner \(a plain field\)/);
  assert.throws(() => publisher.publish("", { x: () => 1 }), /named owner/);
  assert.throws(() => publisher.publish("o", { x: 1 }), /reader function/);
});

// The real composition root: services plus main/state.js, executed as the
// shipped closure executes them.
function composeOwnerState() {
  const services = [
    "services/owner_state.js", "services/state_publisher.js", "services/message_store.js",
    "services/transfer_store.js", "services/settings_store.js", "services/identity_store.js",
    "services/polling_cluster.js",
  ];
  const timers = [];
  return scope([...services, "main/state.js"], {
    setInterval: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    clearInterval: () => {},
  }, "return { state, stateOwners, messageStore, transferStore, settingsStore, identityStore, pollingCluster };");
}

const RETIRED_OWNER_FIELDS = {
  messageStore: ["messages", "groupMessages"],
  transferStore: ["transfers", "transfersById", "transferByDirBlob", "transferRates"],
  settingsStore: ["runtimeSettings", "rendezvousUrls", "chatPrefs"],
  identityStore: ["me", "selfMesh"],
};

test("every migrated owner-page field is read-only on `state` and names its owner", () => {
  const page = composeOwnerState();
  const fresh = load(["services/owner_state.js"]).createOwnerState();
  for (const [ownerName, fields] of Object.entries(RETIRED_OWNER_FIELDS)) {
    for (const field of fields) {
      assert.equal(Object.prototype.hasOwnProperty.call(fresh, field), false,
        `createOwnerState must no longer declare ${field}`);
      assert.equal(page.stateOwners.ownerOf(field), ownerName);
      const before = page.state[field];
      assert.throws(() => { page.state[field] = "raw write"; },
        (e) => e instanceof TypeError && e.message.includes(ownerName), `state.${field}`);
      assert.equal(page.state[field], before, `a refused write must not change state.${field}`);
    }
  }
  assert.deepEqual(page.stateOwners.fields().sort(), Object.values(RETIRED_OWNER_FIELDS).flat().sort());
  // The read path is the owner's live state.
  page.messageStore.appendDirect({ id: "m1" });
  assert.equal(page.state.messages, page.messageStore.direct());
  assert.equal(page.state.messages.length, 1);
  page.transferStore.replaceAll([{ id: "t1" }]);
  assert.equal(page.state.transfersById.get("t1").id, "t1");
});

// ── Message store ───────────────────────────────────────────────────────

function messages() {
  return load(["services/message_store.js"]).createMessageStore();
}

test("message history: snapshots, optimistic sends, echoes and the 1000/800 cap", () => {
  const store = messages();
  assert.deepEqual(store.direct(), []);
  store.appendDirect({ id: "c1", body: "hi", _sendingState: "sending", _attempts: 1 });
  const echo = store.receiveDirect({ id: "c1", body: "hi", ts: 5, _error: "x" });
  assert.equal(store.direct().length, 1, "an echo of a painted id replaces it");
  assert.deepEqual({ ...echo }, { id: "c1", body: "hi", _sendingState: "sent", _attempts: 1, ts: 5, _error: undefined, _queueReason: undefined });
  store.receiveDirect({ id: "c2" });
  assert.deepEqual(store.direct().map((m) => m.id), ["c1", "c2"]);
  for (let i = 0; i < 999; i++) store.receiveDirect({ id: `n${i}` });
  assert.equal(store.direct().length, 800, "past 1000 rows the newest 800 are kept");
  assert.equal(store.direct().at(-1).id, "n998");
  store.replaceDirect(undefined);
  assert.equal(store.direct(), undefined, "a snapshot is kept exactly as the daemon returned it");
  store.replaceGroup([{ id: "g1" }]);
  store.clearAll();
  assert.deepEqual([store.direct(), store.group()], [[], []]);
});

test("group rows merge into a known id or arrive newest-first", () => {
  const store = messages();
  store.replaceGroup([{ id: "a", body: "old", extra: 1 }]);
  store.upsertGroupRow({ id: "a", body: "new" });
  store.upsertGroupRow({ id: "b", body: "b" });
  assert.deepEqual(store.group().map((m) => ({ ...m })), [{ id: "b", body: "b" }, { id: "a", body: "new", extra: 1 }]);
  store.clearGroup();
  assert.deepEqual(store.group(), []);
});

test("live edits, deletes and reactions report whether the target was in memory", () => {
  for (const scope of ["direct", "group"]) {
    const store = messages();
    if (scope === "direct") store.replaceDirect([{ id: "m", body: "x" }]);
    else store.replaceGroup([{ id: "m", body: "x" }]);
    assert.equal(store.editMessage(scope, "m", "y", 7), true);
    assert.equal(store.editMessage(scope, "missing", "y", 7), false);
    assert.deepEqual({ ...store.find(scope, "m") }, { id: "m", body: "y", edited_at_ms: 7 });
    assert.equal(store.applyReaction(scope, "m", "add", "👍", "fp1"), true);
    assert.equal(store.applyReaction(scope, "m", "add", "👍", "fp1"), true);
    store.applyReaction(scope, "m", "add", "👍", "fp2");
    assert.deepEqual(store.find(scope, "m").reactions["👍"], ["fp1", "fp2"], "one reaction per fingerprint");
    store.applyReaction(scope, "m", "remove", "👍", "fp1");
    store.applyReaction(scope, "m", "remove", "👍", "fp2");
    assert.equal("👍" in store.find(scope, "m").reactions, false, "the last reactor removes the emoji");
    assert.equal(store.applyReaction(scope, "m", "remove", "🎉", "fp1"), true);
    assert.equal(store.tombstoneMessage(scope, "m", 9), true);
    assert.deepEqual({ ...store.find(scope, "m"), reactions: undefined },
      { id: "m", body: null, edited_at_ms: 7, deleted: true, deleted_at_ms: 9, reactions: undefined });
  }
  assert.throws(() => messages().editMessage("channel", "m", "y", 1), /unknown message scope/);
});

test("send-state never decorates a tombstoned message", () => {
  const store = messages();
  store.replaceDirect([{ id: "a", peer: "p" }, { id: "b", deleted_at_ms: 3 }, { id: "c", body: "[message deleted]" }]);
  const updated = store.markSendState("a", "queued", { _queueReason: "offline" });
  assert.deepEqual({ ...updated }, { id: "a", peer: "p", _sendingState: "queued", _queueReason: "offline" });
  assert.equal(store.direct()[0], updated, "the row is replaced in place");
  assert.equal(store.markSendState("b", "sent"), null);
  assert.equal(store.markSendState("c", "sent"), null);
  assert.equal(store.markSendState("missing", "sent"), null);
  assert.equal(store.direct()[1]._sendingState, undefined);
});

// ── Transfer store ──────────────────────────────────────────────────────

function transfers(clock = { now: 1000 }) {
  const store = load(["services/transfer_store.js"]).createTransferStore({ now: () => clock.now });
  return { store, clock };
}

test("a ledger snapshot replaces the rows and the by-id map", () => {
  const { store } = transfers();
  const rows = [{ id: "a" }, { id: "b" }];
  store.replaceAll(rows);
  assert.equal(store.list(), rows);
  assert.deepEqual([...store.byId().keys()], ["a", "b"]);
  assert.throws(() => load(["services/transfer_store.js"]).createTransferStore({}), /clock/);
});

test("live transfer events stay newest-first, capped at 80, and evictions leave the map and index", () => {
  const { store } = transfers();
  for (let i = 0; i < 85; i++) {
    store.applyEvent({ id: `t${i}`, updated_ms: i, direction: "out", blob_hash: `B${i}` });
  }
  assert.equal(store.list().length, 80);
  assert.equal(store.list()[0].id, "t84");
  assert.equal(store.byId().has("t0"), false, "an evicted row leaves the by-id map");
  assert.equal(store.byId().size, 80);
  assert.equal(store.dirBlobIndex().has("out|b0"), false, "and the (direction|blob) index");
  assert.equal(store.dirBlobIndex().get("out|b84").id, "t84");
  store.applyEvent({ id: "t84", updated_ms: 1, direction: "out", blob_hash: "B84", status: "complete" });
  assert.equal(store.list().length, 80, "an update replaces, it does not duplicate");
  assert.equal(store.list().find((t) => t.id === "t84").status, "complete");
});

test("the (direction|blob) index is built lazily and maintained incrementally", () => {
  const { store } = transfers();
  store.replaceAll([{ id: "a", direction: "in", blob_hash: "AB" }, { id: "b", direction: "in" }]);
  assert.equal(store.dirBlobIndex(), null);
  store.trackDirBlob({ id: "c", direction: "out", blob_hash: "CD" });
  assert.deepEqual([...store.dirBlobIndex().keys()], ["in|ab"], "without an index, tracking builds it from the map");
  store.trackDirBlob({ id: "c", direction: "out", blob_hash: "CD" });
  assert.equal(store.dirBlobIndex().get("out|cd").id, "c");
  store.trackDirBlob({ id: "d", blob_hash: "EF" });
  assert.equal(store.dirBlobIndex().size, 2, "a row without a direction is not indexed");
});

test("user actions: cancel marks the known row, clearing drops only the list row", () => {
  const { store } = transfers();
  store.replaceAll([{ id: "a", status: "active", metadata: { keep: 1 } }, { id: "b" }]);
  assert.equal(store.markCancelledByUser("a"), true);
  assert.deepEqual({ ...store.byId().get("a") }, {
    id: "a", status: "failed", metadata: { keep: 1, error: "cancelled by user", error_class: "CancelledByUser" },
  });
  assert.equal(store.markCancelledByUser("zzz"), false);
  store.dropListed("b");
  assert.deepEqual(store.list().map((t) => t.id), ["a"]);
  assert.equal(store.byId().has("b"), true, "the panel's Clear removes the list row only, as before");
  store.sampleRate({ id: "a", status: "active", progress_bytes: 1 });
  store.rebuildDirBlobIndex();
  store.clearRecords();
  assert.deepEqual([store.list(), store.byId().size, store.rates().size], [[], 0, 1]);
  store.reset();
  assert.deepEqual([store.list(), store.byId().size, store.rates().size, store.dirBlobIndex()], [[], 0, 0, null]);
});

test("rates: EWMA over snapshots, restamped while paused, restarted on regress, forgotten on terminal", () => {
  const { store, clock } = transfers();
  const t = (progress_bytes, status = "active") => ({ id: "x", status, progress_bytes });
  store.sampleRate(t(0));
  assert.deepEqual({ ...store.rates().get("x") }, { lastBytes: 0, lastTs: 1000, bps: 0 });
  clock.now = 1050;
  store.sampleRate(t(500));
  assert.equal(store.rates().get("x").lastTs, 1000, "a sample under 100 ms is noise and ignored");
  clock.now = 2000;
  store.sampleRate(t(1000));
  assert.equal(store.rates().get("x").bps, 400, "0.6 * 0 + 0.4 * 1000 B/s");
  clock.now = 3000;
  store.sampleRate(t(3000));
  assert.equal(store.rates().get("x").bps, 0.6 * 400 + 0.4 * 2000);
  clock.now = 4000;
  store.sampleRate(t(3500, "paused"));
  assert.deepEqual({ ...store.rates().get("x") }, { lastBytes: 3500, lastTs: 4000, bps: 1040 }, "paused keeps bps, restamps");
  clock.now = 5000;
  store.sampleRate(t(100));
  assert.deepEqual({ ...store.rates().get("x") }, { lastBytes: 100, lastTs: 5000, bps: 0 }, "progress went backwards: restart");
  // Behaviour pinned by test_transfer_progress_v088 (terminal drops the rate).
  assert.equal(store.forgetRate("x"), true);
  assert.equal(store.rates().has("x"), false);
  assert.equal(store.forgetRate("x"), false);
});

// ── Settings store ──────────────────────────────────────────────────────

test("settings: runtime cache, rendezvous URLs, editor hydration and chat preferences", () => {
  const store = load(["services/settings_store.js"]).createSettingsStore();
  assert.equal(store.runtime(), undefined, "absent until the page installs defaults");
  const runtime = store.replaceRuntime({ theme: "dark" });
  assert.equal(store.runtime(), runtime);
  assert.throws(() => store.replaceRuntime(null), /must be an object/);
  store.setRendezvousUrls(["wss://a"]);
  assert.deepEqual(store.rendezvousUrls(), ["wss://a"]);

  assert.equal(store.isDirty(), false);
  store.beginHydration();
  assert.equal(store.markDirty(), false, "programmatic changes while hydrating do not count");
  assert.equal(store.isDirty(), false);
  store.endHydration();
  assert.equal(store.markDirty(), true);
  assert.equal(store.isDirty(), true);
  store.markClean();
  assert.equal(store.isDirty(), false);

  assert.equal(store.setChatPref("peer", "p", "color", "red"), false, "no cache yet: nothing changes");
  assert.equal(store.chatPrefs(), undefined);
  const started = store.startChatPrefs();
  assert.deepEqual(started, { peer: {}, group: {} });
  assert.equal(store.startChatPrefs(), started, "starting twice keeps the cache");
  store.setChatPref("peer", "p", "color", "red");
  store.setChatPref("group", "g", "archived", true);
  assert.deepEqual(store.chatPrefs(), { peer: { p: { color: "red" } }, group: { g: { archived: true } } });
  store.setChatPref("peer", "p", "color", null);
  store.setChatPref("group", "g", "archived", undefined);
  assert.deepEqual(store.chatPrefs(), { peer: { p: {} }, group: { g: {} } });
  store.setChatPref("peer", "p", "wallpaper", "");
  assert.equal(store.chatPrefs().peer.p.wallpaper, "", "an empty string is a value; the picker maps it to null");
  store.replaceChatPrefs(undefined, { g: { color: "blue" } });
  assert.deepEqual(store.chatPrefs(), { peer: {}, group: { g: { color: "blue" } } });
  store.reset();
  assert.deepEqual([store.runtime(), store.rendezvousUrls(), store.chatPrefs(), store.isDirty()], [undefined, undefined, undefined, false]);
});

// ── Identity store ──────────────────────────────────────────────────────

test("identity: /api/me snapshot, local rename and the personal mesh", () => {
  const store = load(["services/identity_store.js"]).createIdentityStore();
  assert.equal(store.me(), null);
  assert.deepEqual({ ...store.rename("Desk") }, { display_name: "Desk" }, "a rename before boot still records the name");
  const me = { fingerprint: "fp", display_name: "Old", onboarding_completed: true };
  store.replaceMe(me);
  assert.equal(store.me(), me);
  const renamed = store.rename("New");
  assert.deepEqual({ ...renamed }, { fingerprint: "fp", display_name: "New", onboarding_completed: true });
  assert.equal(me.display_name, "Old", "a rename never mutates the daemon's snapshot");
  store.replaceSelfMesh({ devices: [1] });
  assert.deepEqual(store.selfMesh(), { devices: [1] });
  store.reset();
  assert.deepEqual([store.me(), store.selfMesh()], [null, null]);
});

// ── Polling cluster (owner transport timers) ────────────────────────────

test("polling cluster: start, pause on 401, resume once, dispose releases every timer", () => {
  let nextId = 0;
  const live = new Map();
  const cluster = load(["services/polling_cluster.js"]).createPollingCluster({
    setInterval: (fn, ms) => { const id = ++nextId; live.set(id, ms); return id; },
    clearInterval: (id) => { live.delete(id); },
  });
  const tasks = [[() => {}, 5000], [() => {}, 4000]];
  assert.equal(cluster.pause(), false, "an empty cluster has nothing to pause");
  assert.equal(cluster.isPaused(), false);
  assert.equal(cluster.resume(tasks), false, "resume only follows a pause");
  cluster.start(tasks);
  cluster.start([[() => {}, 30000]]);
  assert.deepEqual([...live.values()], [5000, 4000, 30000]);
  assert.equal(cluster.pause(), true);
  assert.equal(live.size, 0);
  assert.equal(cluster.isPaused(), true);
  assert.equal(cluster.resume(tasks), true);
  assert.equal(cluster.resume(tasks), false, "a second resume cannot double-fire");
  assert.deepEqual([...live.values()], [5000, 4000]);
  cluster.dispose();
  assert.equal(live.size, 0, "dispose releases every timer");
  assert.deepEqual([cluster.timerIds(), cluster.isPaused()], [[], false]);
  assert.throws(() => load(["services/polling_cluster.js"]).createPollingCluster({}), /interval timers/);
});

// ── Call-log bridge (call driver -> message rendering) ──────────────────

test("the call-log bridge lands CALL_LOG rows in the message store and renders the open chat", () => {
  const ctx = load(["services/message_store.js", "services/call_log_bridge.js"]);
  const store = ctx.createMessageStore();
  let selected = "alice";
  let renders = 0;
  const bridge = ctx.createCallLogBridge({
    messageStore: store,
    getPeers: () => new Map([["alice", { short_id: "alice", fingerprint: "fpA" }]]),
    getSelectedPeer: () => selected,
    renderMessages: () => { renders += 1; },
  });
  assert.equal(bridge.peerShortIdForFp("fpA"), "alice");
  assert.equal(bridge.peerShortIdForFp("nope"), null);
  assert.equal(bridge.peerShortIdForFp(null), null);
  bridge.appendCallLog({ id: "missed-1", t: "CALL_LOG", peer: "alice", call_outcome: "missed" });
  assert.equal(store.direct()[0].id, "missed-1");
  assert.equal(renders, 1);
  selected = "bob";
  bridge.appendCallLog({ id: "ended-2", t: "CALL_LOG", peer: "alice" });
  assert.equal(renders, 1, "another conversation is open: no re-render");
  assert.throws(() => bridge.appendCallLog({ id: "x", t: "TEXT", peer: "alice" }), /CALL_LOG rows only/);
  for (let i = 0; i < 999; i++) bridge.appendCallLog({ id: `c${i}`, t: "CALL_LOG", peer: "bob" });
  assert.equal(store.direct().length, 800, "call-log rows share the history cap");
  assert.equal(Object.isFrozen(bridge), true);
  assert.throws(() => ctx.createCallLogBridge({}), /message store/);
});

// ── Owned record (calls group) ──────────────────────────────────────────

test("an owned record: live read-only view, closed schema, atomic update", () => {
  const { createOwnedRecord } = load(["services/owned_record.js"]);
  const record = createOwnedRecord("media", { a: 1, b: null, list: [] });
  const { view } = record;
  assert.deepEqual(Object.keys(view), ["a", "b", "list"]);
  assert.equal(JSON.stringify(view), '{"a":1,"b":null,"list":[]}');
  // Sloppy-mode code (the call closure) must fail loudly too.
  const sloppy = vm.createContext({ view });
  for (const statement of ["view.a = 2", "view.added = 1", "delete view.a", "Object.defineProperty(view, 'a', { value: 3 })"]) {
    assert.throws(() => new vm.Script(statement).runInContext(sloppy), /owned state/, statement);
  }
  assert.equal(view.a, 1);
  assert.equal(record.set("a", 5), 5);
  assert.equal(view.a, 5, "the view reads the record live");
  assert.equal(record.increment("a"), 6);
  assert.equal(record.increment("a", -2), 4);
  assert.throws(() => record.set("typo", 1), /has no field typo/);
  assert.throws(() => record.update({ a: 9, typo: 1 }), /has no field typo/);
  assert.equal(view.a, 4, "an update with an unknown field writes nothing");
  record.update({ a: 7, b: "x" });
  assert.deepEqual([view.a, view.b], [7, "x"]);
  assert.equal(view.missing, undefined);
  assert.throws(() => createOwnedRecord("", {}), /named owner/);
});

// ── Call state ──────────────────────────────────────────────────────────

function callState(extra = {}) {
  const cleared = [];
  const ctx = load(["services/owned_record.js", "services/call_state.js"]);
  const state = ctx.createCallState({ clearInterval: (id) => cleared.push(id), ...extra });
  return { state, view: state.view, cleared, ctx };
}

test("call state: the view is read-only and writes go through the owner", () => {
  const { state, view } = callState();
  assert.throws(() => { view.activeCallId = "x"; }, /callUI\.activeCallId is owned state/);
  // Behaviour pinned by test_call_ui_media / test_call_ui_surfaces.
  state.set("localMediaReady", true);
  assert.equal(view.localMediaReady, true);
  state.set("pendingRemoteOffer", null);
  assert.equal(view.pendingRemoteOffer, null);
  assert.equal(callState().view.pendingRemoteOffer, undefined, "absent until an offer arrives, as before");
  state.acceptCall("call-1");
  assert.equal(view.acceptedCallIds.has("call-1"), true);
  assert.equal(state.forgetAcceptedCall("call-1"), true);
  assert.throws(() => state.set("activeCalId", "typo"), /has no field activeCalId/);
});

test("call state: signaling bookkeeping keeps arrival order and forgets per connection", () => {
  const { state, view } = callState();
  state.queueIceCandidate({ candidate: "a" });
  state.queueIceCandidate({ candidate: "b" });
  state.markIceApplied("k1");
  state.markRemoteOfferApplied("o1");
  state.markRemoteAnswerApplied("a1");
  state.update({ sdpOfferInFlight: true, sdpAnswerInFlight: true, lastLocalOfferSdp: "v=0", lastLocalAnswerSdp: "v=0" });
  assert.deepEqual(state.takeQueuedIceCandidates().map((c) => c.candidate), ["a", "b"]);
  assert.equal(view.pendingIceCandidates.length, 0);
  state.queueIceCandidate({ candidate: "c" });
  const iceKeys = view.appliedIceKeys;
  state.forgetIceSignals();
  assert.deepEqual([view.pendingIceCandidates.length, view.appliedIceKeys.size, view.appliedRemoteOfferKeys.size], [0, 0, 1]);
  assert.equal(view.appliedIceKeys, iceKeys, "applied-key sets are cleared in place");
  state.forgetNegotiation();
  assert.deepEqual([view.appliedRemoteOfferKeys.size, view.appliedRemoteAnswerKeys.size, view.sdpOfferInFlight,
    view.sdpAnswerInFlight, view.lastLocalOfferSdp, view.lastLocalAnswerSdp], [0, 0, false, false, "", ""]);
});

test("call state: bounded logs, repair diagnosis and per-call tracking", () => {
  const { state, view } = callState();
  for (let i = 0; i < 15; i++) state.recordAutoTrace({ i });
  assert.deepEqual(view.autoTraceBuffer.map((t) => t.i).slice(0, 2), [14, 13]);
  assert.equal(view.autoTraceBuffer.length, 12);
  for (let i = 0; i < 12; i++) state.recordCallHistory({ i });
  assert.equal(view.callHistory.length, 10);
  for (let i = 0; i < 6; i++) state.recordOneEvent({ text: String(i) });
  assert.deepEqual(view.oneEvents.map((e) => e.text), ["5", "4", "3", "2"]);
  state.clearOneEvents();
  assert.deepEqual(view.oneEvents, []);

  const counts = state.countRepairDiagnosis("ice_failed", 4);
  assert.equal(counts, view.repairDiagnosisCounts, "counts are updated in place and returned for reading");
  state.countRepairDiagnosis("ice_failed", 9);
  assert.deepEqual([view.repairDiagnosisCounts.ice_failed, view.repairEscalationScore], [2, 10], "the score caps at 10");
  state.set("lastRepairDiagnosis", { kind: "ice_failed" });
  state.clearRepairDiagnosis();
  assert.deepEqual([view.repairDiagnosisCounts, view.lastRepairDiagnosis], [{}, null]);

  state.stampBackendCooldown("ice_restart", 5);
  state.stampAcceptRetry("c", 6);
  state.stampRejoinAttempt("c", 7);
  assert.deepEqual([view.backendActionCooldowns.ice_restart, view.lastAcceptRetryMs.c, view.lastRejoinAttemptMs.c], [5, 6, 7]);

  assert.equal(view._callTracking, undefined);
  state.startCallTracking();
  const table = view._callTracking;
  state.startCallTracking();
  assert.equal(view._callTracking, table, "starting twice keeps the table");
  state.trackCall("c1", { reachedActive: false, endedAt: null });
  assert.equal(state.markTrackedCallActive("c1"), true);
  assert.equal(state.markTrackedCallActive("nope"), false);
  const ended = state.endTrackedCall("c1", 99);
  assert.deepEqual({ ...ended }, { reachedActive: true, endedAt: 99 });
  assert.equal(state.endTrackedCall("c1", 100), null, "a call ends once");
  assert.equal(state.endTrackedCall("nope", 100), null);
  state.forgetTrackedCall("c1");
  assert.deepEqual(Object.keys(view._callTracking), []);
});

test("call state: resetMediaSession clears exactly the media session and keeps call identity and history", () => {
  const { state, view, ctx } = callState();
  const fresh = ctx.createCallState().view;
  const sessionFields = [
    "pendingIceCandidates", "appliedIceKeys", "appliedRemoteOfferKeys", "appliedRemoteAnswerKeys", "localMediaReady",
    "lastLocalOfferSdp", "lastLocalAnswerSdp", "lastOfferSendMs", "lastAnswerSendMs", "lastLocalOfferCreatedMs",
    "remoteOfferCollisionCount", "lastMetricsSnapshot", "lastMediaRepairMs", "lastInboundVideoBytes",
    "lastInboundAudioBytes", "stalledMediaTicks", "lastInboundPacketsLost", "lastInboundPacketsReceived",
    "qualityEwmaRttMs", "qualityEwmaLoss", "qualityBadTicks", "qualityGoodTicks", "lastUserVisibleRepairMs",
    "adaptationLevel", "tauPressureTicks", "tauStableTicks", "lastTauAdaptMs", "tauRiskEwma", "tauCoherenceEwma",
    "tauSurpriseEwma", "tauBandwidthEwmaKbps", "tauLastDecision", "lastCaptureProfile", "mediaRepairStage",
    "lastPlaybackReviveMs", "lastPcRebuildMs", "lastRemoteMediaMovingMs", "lastRepairDiagnosis",
    "repairDiagnosisCounts", "repairEscalationScore", "acceptedCallIds", "lastAcceptRetryMs",
  ];
  // Dirty every field with a value distinct from its initial one.
  const dirty = {};
  for (const key of Object.keys(view)) {
    const initial = view[key];
    if (initial instanceof Set) continue;
    dirty[key] = Array.isArray(initial) ? [{ dirty: key }] : { dirty: key };
  }
  state.update(dirty);
  for (const key of ["appliedIceKeys", "appliedRemoteOfferKeys", "appliedRemoteAnswerKeys", "acceptedCallIds"]) view[key].add("dirty");
  state.resetMediaSession();
  for (const key of Object.keys(view)) {
    if (sessionFields.includes(key)) {
      if (view[key] instanceof Set) assert.equal(view[key].size, 0, key);
      else assert.deepEqual(view[key], fresh[key], `${key} resets to its initial value`);
    } else {
      assert.deepEqual(view[key], dirty[key], `${key} is not media-session state and must survive`);
    }
  }
});

test("call state: dispose releases the telemetry timers it holds", () => {
  const { state, view, cleared } = callState();
  state.update({ metricsTimer: 11, mediaWatchdogTimer: 12 });
  state.dispose();
  assert.deepEqual(cleared, [11, 12]);
  assert.deepEqual([view.metricsTimer, view.mediaWatchdogTimer], [null, null]);
  state.dispose();
  assert.deepEqual(cleared, [11, 12], "nothing left to release");
});

// ── Media state ─────────────────────────────────────────────────────────

test("media state: read-only view and the three end-of-call resets", () => {
  const ctx = load(["services/owned_record.js", "services/media_state.js"]);
  const media = ctx.createCallMediaState();
  const fresh = ctx.createCallMediaState().view;
  const view = media.view;
  assert.throws(() => { view.preferRelayNext = true; }, /media\.preferRelayNext is owned state/);
  // Behaviour pinned by test_call_ui_media (relay preference, candidates, captions).
  media.set("preferRelayNext", true);
  media.set("localCandidateAddresses", ["127.0.0.1"]);
  media.update({ captionRecognizer: { abort() {} }, captionsStarting: true });
  assert.deepEqual([view.preferRelayNext, view.localCandidateAddresses, view.captionsStarting], [true, ["127.0.0.1"], true]);
  media.update({ captionRecognizer: null, captionsStarting: false });
  assert.deepEqual([view.captionRecognizer, view.captionsStarting], [null, false]);

  const groups = {
    resetRoute: ["iceConfigReady", "localCandidateAddresses", "iceSignalChain", "iceHelperReady", "iceRelayReady",
      "routePolicy", "forceRelayOnRepair", "preferRelayNext", "transceiversReady"],
    resetSessionControls: ["screenStream", "cameraVideoTrack", "screenSharing", "backgroundBlur", "reconnecting",
      "expectRemoteVideo", "expectRemoteAudio", "transceiversReady", "held", "captionsStarting"],
    resetPresentation: ["layoutMode", "voiceProcessing", "muted", "cameraOff"],
  };
  for (const [reset, fields] of Object.entries(groups)) {
    const dirty = {};
    for (const key of Object.keys(view)) dirty[key] = { dirty: key };
    media.update(dirty);
    media[reset]();
    for (const key of Object.keys(view)) {
      if (!fields.includes(key)) assert.deepEqual(view[key], dirty[key], `${reset} must keep ${key}`);
      else if (key === "iceSignalChain") assert.equal(typeof view[key].then, "function");
      else assert.deepEqual(view[key], fresh[key], `${reset} resets ${key}`);
    }
  }
});

// ── Call driver host adapters ───────────────────────────────────────────

function hostAdapters(window) {
  return scope(["calls/host.js"], { window },
    "return { api, toast, errorToastBody, _newClientMsgId, returnToOneHealthGuideIfPending, selectPeer, _escapeHtml };");
}

test("the call driver reaches owner services only through the host bridge, and degrades without it", async () => {
  const lonely = hostAdapters({});
  assert.doesNotThrow(() => lonely.toast("hi", "info", 1));
  assert.doesNotThrow(() => lonely.selectPeer("alice"));
  assert.equal(lonely.returnToOneHealthGuideIfPending(), false);
  assert.equal(lonely.errorToastBody(new Error("boom")), "boom");
  await assert.rejects(lonely.api.post("/api/x", {}), /needs the One Link owner page/);
  await assert.rejects(lonely.api.upload("p", {}, {}), /needs the One Link owner page/);
  assert.throws(() => lonely._newClientMsgId(), /needs the One Link owner page/);

  const calls = [];
  const host = {
    post: async (...args) => { calls.push(["post", ...args]); return { ok: true }; },
    upload: async (...args) => { calls.push(["upload", ...args]); return { queued: true }; },
    newClientMsgId: () => "intent-1",
    toast: (...args) => calls.push(["toast", ...args]),
    errorToastBody: () => "translated",
    returnToOneHealthGuideIfPending: () => true,
    selectPeer: (id) => calls.push(["selectPeer", id]),
  };
  const hosted = hostAdapters({ __oneLinkCallHost: host });
  assert.deepEqual(await hosted.api.post("/api/sovereignty/preset", { name: "x" }), { ok: true });
  await hosted.api.upload("p", "file", { clientDeliveryId: "d" });
  hosted.toast("t", "ok", 5);
  hosted.selectPeer("alice");
  assert.equal(hosted._newClientMsgId(), "intent-1");
  assert.equal(hosted.errorToastBody(new Error("raw")), "translated");
  assert.equal(hosted.returnToOneHealthGuideIfPending(), true);
  assert.deepEqual(calls.map((c) => c[0]), ["post", "upload", "toast", "selectPeer"]);
  assert.equal(Object.isFrozen(hosted.api), true);
});

test("the call driver's HTML escaper is the owner page's, character for character", () => {
  const ownerBody = read("main/peers.js").match(/function _escapeHtml\(s\) \{[\s\S]*?\n  \}/)[0];
  const ownerEscape = new vm.Script(`(${ownerBody.replace("function _escapeHtml", "function")})`).runInNewContext({});
  const callEscape = hostAdapters({})._escapeHtml;
  const samples = ["", "plain", "<img src=x onerror=alert(1)>", "\"'&<>", "&amp;", "</script>", "a\u0000b", 42, null, "<<>>&&\"\"''"];
  for (const value of samples) assert.equal(callEscape(value), ownerEscape(value), JSON.stringify(value));
  assert.equal(callEscape("<a href='x'>&</a>"), "&lt;a href=&#39;x&#39;&gt;&amp;&lt;/a&gt;");
});

// ── Feature code that stayed in its module, exercised from its source ──

// The slice of main/messages.js that owns the arrival baseline: its private
// render memo, the scroll capture/restore pair and the reset other modules
// call on a conversation switch (no DOM listeners are registered here).
function messageScrollTracker() {
  const source = read("main/messages.js");
  const slice = source.slice(source.indexOf("  const NEAR_BOTTOM_PX = 80;"), source.indexOf("  // Pill tap -> smooth scroll"));
  const document = { querySelector: () => null };
  const state = { runtimeSettings: { auto_scroll_new_messages: false } };
  return new Function("document", "state", "requestAnimationFrame", "setTimeout",
    `${slice}\nreturn { _captureScrollState, _smartScrollAfter, _resetRenderedMessageCount };`)(
    document, state, () => {}, () => {});
}

test("a conversation switch resets the message arrival baseline through its owner", () => {
  const tracker = messageScrollTracker();
  const scrolledUp = { scrollHeight: 1000, scrollTop: 0, clientHeight: 100, lastElementChild: null };
  assert.equal(tracker._captureScrollState(scrolledUp).prevLen, 0);
  tracker._smartScrollAfter(scrolledUp, { wasAtBottom: false, prevLen: 0 }, 12);
  assert.equal(tracker._captureScrollState(scrolledUp).prevLen, 12, "the renderer remembers what it drew");
  tracker._resetRenderedMessageCount();
  assert.equal(tracker._captureScrollState(scrolledUp).prevLen, 0,
    "after a switch the new conversation's history is not counted as new arrivals");
});

test("the owner polling cluster refreshes peers, transfers, status, health, fabric and groups", () => {
  const source = read("main/session.js");
  const body = source.slice(source.indexOf("  function _mainPollTasks()"), source.indexOf("  function _pauseMainPollTimers()"));
  const names = ["refreshPeers", "refreshTransfers", "refreshStatus", "refreshOneHealth", "refreshFabricTruth", "refreshGroups"];
  const fns = names.map((name) => Object.defineProperty(() => {}, "name", { value: name }));
  const tasks = new Function(...names, `${body}\nreturn _mainPollTasks();`)(...fns);
  assert.deepEqual(tasks.map(([fn, ms]) => [fn.name, ms]), [
    ["refreshPeers", 5000], ["refreshTransfers", 4000], ["refreshStatus", 8000],
    ["refreshOneHealth", 15000], ["refreshFabricTruth", 30000], ["refreshGroups", 12000],
  ]);
});

test("media state records the daemon's route policy as one step", () => {
  const media = load(["services/owned_record.js", "services/media_state.js"]).createCallMediaState();
  media.recordRoutePolicy({ mode: "relay_first", best_relay_health: "good", best_relay_score: "0.75", credential_expires_at_ms: 99 });
  assert.deepEqual([media.view.routePolicyDetail.mode, media.view.bestRelayHealth, media.view.bestRelayScore, media.view.turnCredentialExpiresAtMs],
    ["relay_first", "good", 0.75, 99]);
  media.recordRoutePolicy(undefined);
  assert.deepEqual([media.view.routePolicyDetail, media.view.bestRelayHealth, media.view.bestRelayScore, media.view.turnCredentialExpiresAtMs],
    [null, "", null, null], "no policy: nothing stale survives");
  media.recordRoutePolicy({ best_relay_score: "not a number", credential_expires_at_ms: 0 });
  assert.deepEqual([media.view.bestRelayScore, media.view.turnCredentialExpiresAtMs], [null, null]);
});

test("a call event the call driver throws on is counted and logged, and the event stream survives", () => {
  const sockets = [];
  class FakeWebSocket {
    constructor(url, protocols) { this.url = url; this.protocols = protocols; sockets.push(this); }
    close() {}
  }
  const logged = [];
  const window = { handleLivingPresenceCallEvent: () => { throw new Error("driver bug"); } };
  const page = scope(["main/events.js"], {
    window,
    location: { protocol: "https:", host: "127.0.0.1:7117" },
    WebSocket: FakeWebSocket,
    LiveRefresh: { onOpen() {}, onClose() {} },
    _ownerBearerToken: () => "",
    console: { ...console, error: (...args) => logged.push(args) },
  }, "return { connectWS, callEventHandlerFailures };");
  page.connectWS();
  const ws = sockets[0];
  assert.equal(ws.url, "wss://127.0.0.1:7117/api/events");
  assert.equal(page.callEventHandlerFailures(), 0);
  assert.doesNotThrow(() => ws.onmessage({ data: JSON.stringify({ type: "call_event", tail_kind: "phase_changed" }) }));
  assert.doesNotThrow(() => ws.onmessage({ data: JSON.stringify({ type: "call_event", tail_kind: "show_ring" }) }));
  assert.equal(page.callEventHandlerFailures(), 2, "every failure is counted for the diagnostic report");
  assert.equal(logged.length, 2);
  assert.match(String(logged[0][0]), /call event handler failed \(1 so far\)/);
  assert.equal(logged[0][1], "phase_changed");
  assert.equal(logged[0][2].message, "driver bug");
  window.handleLivingPresenceCallEvent = () => true;
  ws.onmessage({ data: JSON.stringify({ type: "call_event" }) });
  assert.equal(page.callEventHandlerFailures(), 2);
});
