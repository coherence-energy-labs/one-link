"use strict";

// Regression for the call-end defect the ownership census surfaced: the call
// driver named the owner closure's `state` / `renderMessages`, which do not
// exist in its own closure. Ending any tracked call that had a peer
// fingerprint threw a ReferenceError before teardown, so the ring, call
// surfaces and local media (microphone, camera) were never stopped, and the
// owner page's WebSocket handler swallowed the error.
//
// The driver now tears down first and adds the missed/ended bubble last,
// through the owner page's explicit window.__oneLinkCallLog bridge. These
// checks run the shipped driver (set ONE_LINK_OWNER_HTML to run them against
// another build: against the pre-fix page they fail).
const assert = require("node:assert/strict");
const test = require("node:test");
const { createCallDriver } = require("./call_driver_harness.cjs");

function recordingBridge({ throws = false } = {}) {
  const rows = [];
  return {
    rows,
    bridge: {
      peerShortIdForFp: (fp) => (fp === "peer-fp" ? "alice" : null),
      appendCallLog: (row) => {
        if (throws) throw new Error("bridge exploded");
        rows.push(row);
      },
    },
  };
}

function removed(log, selector, name = "show") {
  return log.some(([op, sel, ...names]) => op === "class.remove" && sel === selector && names.includes(name));
}

function assertTornDown(driver) {
  const { log, window } = driver;
  assert(removed(log, "#call-outgoing-overlay"), "hideOutgoingOverlay ran");
  assert(removed(log, "#call-incoming-overlay"), "hideIncomingRing ran");
  assert(removed(log, "#call-active-surface"), "hideActiveSurface ran");
  assert(log.some(([op, sel]) => op === "srcObject=null" && sel === "#call-local-video"), "stopAllMedia ran");
  assert(removed(log, "#call-local-video"), "stopAllMedia detached the local preview");
  assert.equal(window._livingPresenceMedia.pc, null, "the peer connection is released");
  assert.equal(window._livingPresenceMedia.localStream, null, "local capture is released");
  assert.deepEqual(Object.keys(window._livingPresenceCallUI._callTracking), [], "the call left the tracking table");
}

const ring = { type: "call_event", tail_kind: "show_ring", call_id: "call-in-1",
  peer_label: "Phone", peer_master_vk_hex: "peer-fp", kind: "voice" };
const ended = (callId, cause = "peer_declined") =>
  ({ type: "call_event", tail_kind: "phase_changed", call_id: callId, new_phase: "ended", end_cause: cause });

test("an inbound call that ends unanswered tears down and logs a missed bubble through the bridge", async () => {
  const { rows, bridge } = recordingBridge();
  const driver = createCallDriver({ window: { __oneLinkCallLog: bridge } });
  const handle = driver.window.handleLivingPresenceCallEvent;
  assert.equal(handle(ring), true);
  assert.doesNotThrow(() => handle(ended("call-in-1")));
  assertTornDown(driver);
  assert.equal(rows.length, 1, "the missed bubble landed in the owner page's message store");
  assert.deepEqual(
    { id: rows[0].id, t: rows[0].t, peer: rows[0].peer, outcome: rows[0].call_outcome, label: rows[0].call_end_label },
    { id: "missed-call-in-1", t: "CALL_LOG", peer: "alice", outcome: "missed", label: "Declined" },
  );
  assert.deepEqual(driver.errors, []);
});

test("an outgoing call with live microphone and camera stops capture when it ends", async () => {
  const { rows, bridge } = recordingBridge();
  const driver = createCallDriver({ window: { __oneLinkCallLog: bridge } });
  const w = driver.window;
  await w.startLivingPresenceCall("peer-fp", "Computer 2", { video: true });
  await driver.settle();
  const stream = w._livingPresenceMedia.localStream;
  assert(stream, "the call captured local media");
  assert.deepEqual(stream.getTracks().map((t) => t.readyState), ["live", "live"]);
  w.handleLivingPresenceCallEvent({ type: "call_event", tail_kind: "phase_changed", call_id: "call-out-1",
    new_phase: "active", peer_master_vk_hex: "peer-fp" });
  assert.doesNotThrow(() => w.handleLivingPresenceCallEvent(ended("call-out-1", "user_hangup_local")));
  assert.deepEqual(stream.getTracks().map((t) => t.readyState), ["ended", "ended"], "microphone and camera stopped");
  assert.equal(driver.connections[0].closed, true);
  assertTornDown(driver);
  assert.equal(w._livingPresenceCallUI.activeCallId, null);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].call_outcome, "ended", "a call that reached active logs an ended bubble");
  assert.equal(rows[0].id, "ended-call-out-1");
});

test("without an owner page (no bridge) call-end teardown still runs in full", () => {
  const driver = createCallDriver();
  const handle = driver.window.handleLivingPresenceCallEvent;
  handle(ring);
  assert.doesNotThrow(() => handle(ended("call-in-1")));
  assertTornDown(driver);
});

test("a failing bridge never skips teardown; the failure is logged, not thrown", () => {
  const { bridge } = recordingBridge({ throws: true });
  const driver = createCallDriver({ window: { __oneLinkCallLog: bridge } });
  const handle = driver.window.handleLivingPresenceCallEvent;
  handle(ring);
  assert.doesNotThrow(() => handle(ended("call-in-1")));
  assertTornDown(driver);
  assert(driver.errors.some((line) => line.includes("bridge exploded")), "the bubble failure is logged");
});
