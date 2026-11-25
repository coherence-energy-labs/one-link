"""RUN-01 regression: a browser createOffer() that does not settle.

Mechanism (reproduced on Windows Firefox 153 / Playwright 1.62, see the RUN-01
root-cause note): on a loaded host, the Firefox parent process can stop
servicing content -> parent IPC. The observed holds ran from 2 seconds to more
than 12 minutes. createOffer() waits on one such round trip, the permission
request in PeerConnection.sys.mjs `_createAnOffer` -> `_getPermission`, so it
does not settle. A fresh RTCPeerConnection, a fetch and enumerateDevices issued
during the hold are held too, and all are released within about 30 ms of each
other. The gate is therefore the process, not one connection. The pairing flow
awaits createOffer() with no step bound. When the hold outlasts the 90-second
pairing deadline, pairing fails and no offer ever reaches the daemon. At
1279a450 the page still shows "negotiating"; at 798026a it shows "timed out"
with the stage `creating_offer`.

These tests execute the shipped `_runAutoPairFlow` in Node with a stub
RTCPeerConnection whose createOffer() is held. They pin three things:

1. The flow is bounded even when createOffer() never settles. The deadline
   rejection names the `creating_offer` stage, and the timer and connection
   are released.
2. If the browser releases createOffer() after the deadline, the late result
   must not rewrite the user-visible failure. The status must stay "timed out"
   instead of becoming a misleading "offer failed", and no WebSocket may be
   opened.
3. A stall shorter than the deadline still completes signaling. The flow must
   then send exactly one signed offer over the WebSocket.

Discrimination (measured 2026-11-25): against the peer.html assembled at
798026a (and unchanged at 516b32f), tests 1 and 2[resolve] and 2[reject] FAIL
and test 3 passes. Test 1 fails because the flow's returned promise stays
pending while createOffer() is held, even though the internal deadline already
fired; this is the same thing the live HEAD run showed, where
`__olIdentityPairError` was never set. Tests 2 fail because the late result
rewrites the status to "offer failed: InvalidStateError ...". With
peer_offer_step_race.patch applied (race the held calls against `flowDone`,
and re-check `flowSettled` after each await and in the catch), all four pass,
and the five existing test_peer_pairing_progress.py cases still pass. The
canonical source of the offer step is frontend/peer/pairing/auto_pair.js;
patch it there and regenerate peer.html.

Place this file in tests/ next to test_peer_pairing_progress.py. It uses the
same Node harness conventions and skips cleanly when Node is absent.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def _section(start: str, end: str) -> str:
    source = Path("src/one_link/web/peer.html").read_text(encoding="utf-8")
    first = source.index(start)
    return source[first:source.index(end, first)]


def _flow() -> str:
    factory = _section("function createPeerProgress(", "\n}\n") + "\n}\n"
    progress = factory + "const { _pairingProgress } = createPeerProgress({ state, performance });\n"
    return progress + _section(
        "async function _runAutoPairFlow(pair)", "// ── v0.20.2 — daemon DataChannel router",
    )


def _run(script: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for executable pairing lifecycle checks")
    result = subprocess.run(
        [node, "--input-type=commonjs"], input=script, text=True,
        capture_output=True, timeout=20, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# Shared stubs: everything _runAutoPairFlow touches before and around the
# offer step. The RTCPeerConnection stub records lifecycle calls. Its
# createOffer() returns a promise the test settles explicitly, which simulates
# the browser-held offer.
_PRELUDE = r"""
const assert = require('node:assert/strict');
const state = {rec: {public_key_b64u: 'pk', fingerprint: 'fp', private_key_jwk: {}}};
const timers = new Map();
let nextTimer = 1;
const setTimeout = (fn, ms) => { const id = nextTimer++; timers.set(id, {fn, ms}); return id; };
const clearTimeout = (id) => { timers.delete(id); };
const fireTimer = (ms) => {
  for (const [id, t] of timers) {
    if (t.ms === ms) { timers.delete(id); t.fn(); return true; }
  }
  return false;
};
const button = { addEventListener: () => {}, removeEventListener: () => {} };
const $ = () => button;
const show = () => {};
const hide = () => {};
const _showOnly = () => {};
const _autopairShowHost = () => {};
const statuses = [];
const _autopairSetState = (...args) => { statuses.push(args); };
const _autopairPreflight = () => null;
const _waitForIdentity = async () => state.rec;
const loadPublicIceConfig = async () => ({iceServers: [], localCandidateAddresses: []});
const AUTOPAIR_DAEMON_CONTROL_LABEL = 'control';
const AUTOPAIR_DAEMON_BULK_LABEL = 'bulk';
const _registerDaemonDc = () => new Promise(() => {});
const _routeDaemonDcMessage = () => {};
const _descriptionForSignal = ({pc}) => ({type: 'offer', sdp: pc.localDescription.sdp});
const _canonicalJson = (value) => JSON.stringify(value);
const _signEd25519 = async () => new Uint8Array([1, 2, 3]);
const bytesToB64Url = () => 'sig';
const _verifySignedDaemonAnswer = async () => {};
const _waitForIceGatheringComplete = async () => true;
const savePeer = async () => {};
const _refreshDaemonRoster = async () => {};
const TextEncoder = globalThis.TextEncoder;
const performance = globalThis.performance;
const sockets = [];
class WebSocket {
  constructor(url) { this.url = url; this.sent = []; this.closed = false; sockets.push(this); }
  send(data) { this.sent.push(JSON.parse(data)); }
  close() { this.closed = true; }
}
const connections = [];
let settleOffer;
class RTCPeerConnection {
  constructor() {
    this.connectionState = 'new';
    this.iceConnectionState = 'new';
    this.iceGatheringState = 'new';
    this.closed = false;
    this.localDescription = null;
    connections.push(this);
  }
  createDataChannel(label) { return {label, readyState: 'connecting'}; }
  createOffer() {
    return new Promise((resolve, reject) => { settleOffer = {resolve, reject}; });
  }
  async setLocalDescription(offer) {
    if (this.closed) throw new Error('InvalidStateError: RTCPeerConnection is closed');
    this.localDescription = offer;
  }
  close() { this.closed = true; this.connectionState = 'closed'; }
}
const tick = () => new Promise((resolve) => globalThis.setTimeout(resolve, 0));
"""


def test_held_create_offer_is_bounded_named_and_released() -> None:
    _run(_PRELUDE + _flow() + r"""
(async () => {
  const flow = _runAutoPairFlow({daemon_fingerprint: 'fp', pair_token: 't', ws_url: 'wss://x/y'});
  let rejection = null;
  flow.catch((error) => { rejection = error; });
  for (let i = 0; i < 20 && !settleOffer; i++) await tick();
  assert.ok(settleOffer, 'flow must reach createOffer()');
  assert.equal(state.autopair_diagnostics.phase, 'creating_offer');
  // The browser never releases the offer: only the pairing deadline remains.
  assert.ok(fireTimer(90000), 'a pairing deadline must exist while createOffer() is held');
  for (let i = 0; i < 20 && !rejection; i++) await tick();
  assert.ok(rejection, 'a held createOffer() must not leave the flow pending forever');
  assert.match(String(rejection.message), /creating_offer/,
    'the deadline error must name the stage the browser was holding');
  assert.equal(connections[0].closed, true, 'the held connection must be closed');
  assert.equal(sockets.length, 0, 'no signaling socket may open without an offer');
  assert.equal(timers.size, 0, 'no pairing timer may outlive the settled flow');
})().catch((error) => { console.error(error); process.exitCode = 1; });
""")


@pytest.mark.parametrize("late", ["resolve", "reject"])
def test_offer_released_after_deadline_does_not_rewrite_the_failure(late: str) -> None:
    _run(_PRELUDE + _flow() + f"""
(async () => {{
  const flow = _runAutoPairFlow({{daemon_fingerprint: 'fp', pair_token: 't', ws_url: 'wss://x/y'}});
  flow.catch(() => {{}});
  for (let i = 0; i < 20 && !settleOffer; i++) await tick();
  assert.ok(fireTimer(90000));
  for (let i = 0; i < 5; i++) await tick();
  const timedOut = statuses[statuses.length - 1];
  assert.equal(timedOut[1], 'timed out');
  // Firefox releases the held operation after the flow already failed.
  if ('{late}' === 'resolve') settleOffer.resolve({{type: 'offer', sdp: 'v=0'}});
  else settleOffer.reject(new Error('InvalidStateError: RTCPeerConnection is gone'));
  for (let i = 0; i < 20; i++) await tick();
  assert.deepEqual(statuses[statuses.length - 1], timedOut,
    'a late createOffer() result must not replace the timed-out status');
  assert.equal(sockets.length, 0, 'a settled flow must not open signaling later');
}})().catch((error) => {{ console.error(error); process.exitCode = 1; }});
""")


def test_offer_held_below_deadline_still_sends_one_signed_offer() -> None:
    _run(_PRELUDE + _flow() + r"""
(async () => {
  const flow = _runAutoPairFlow({daemon_fingerprint: 'fp', pair_token: 't', ws_url: 'wss://x/y'});
  flow.catch(() => {});
  for (let i = 0; i < 20 && !settleOffer; i++) await tick();
  // A held-then-released offer (the 12-53 s stalls observed) must not be
  // treated as failure while the pairing deadline has not expired.
  settleOffer.resolve({type: 'offer', sdp: 'v=0'});
  for (let i = 0; i < 40 && sockets.length === 0; i++) await tick();
  assert.equal(sockets.length, 1, 'released offer must proceed to signaling');
  sockets[0].onopen();
  assert.equal(sockets[0].sent.length, 1);
  assert.equal(sockets[0].sent[0].t, 'offer');
  assert.equal(sockets[0].sent[0].signature, 'sig');
  assert.ok(timers.size >= 1, 'the pairing deadline stays armed until connected');
})().catch((error) => { console.error(error); process.exitCode = 1; });
""")


# Every browser call the flow awaits before signaling can be held the same
# way (RUN-01: a stalled parent process also held fetch and new connections).
# Each one races the flow's own deadline: the caller is rejected with the
# stage named, the connection is released, a late result changes nothing,
# and no signaling socket ever opens.
_HELD_STEP_STUBS = {
    "ice_config": (
        "const loadPublicIceConfig = async () => ({iceServers: [], localCandidateAddresses: []});",
        "const loadPublicIceConfig = () => new Promise((resolve, reject) => {"
        " held = {resolve: () => resolve({iceServers: [], localCandidateAddresses: []}), reject}; });",
    ),
    "set_local_description": (
        "  async setLocalDescription(offer) {",
        "  setLocalDescription(offer) {\n"
        "    return new Promise((resolve, reject) => {\n"
        "      held = {resolve: () => { this.localDescription = offer; resolve(); }, reject};\n"
        "    });\n"
        "  }\n"
        "  async _unusedSetLocalDescription(offer) {",
    ),
    "ice_gathering": (
        "const _waitForIceGatheringComplete = async () => true;",
        "const _waitForIceGatheringComplete = () => new Promise((resolve, reject) => {"
        " held = {resolve: () => resolve(true), reject}; });",
    ),
    "signing": (
        "const _signEd25519 = async () => new Uint8Array([1, 2, 3]);",
        "const _signEd25519 = () => new Promise((resolve, reject) => {"
        " held = {resolve: () => resolve(new Uint8Array([1, 2, 3])), reject}; });",
    ),
}
_HELD_STAGE = {
    "ice_config": "ice_config",
    "set_local_description": "creating_offer",
    "ice_gathering": "gathering_ice",
    "signing": "signing_offer",
}


def _held_prelude(step: str) -> str:
    original, held = _HELD_STEP_STUBS[step]
    assert _PRELUDE.count(original) == 1, original
    prelude = _PRELUDE.replace(original, held)
    # Steps after the offer need the offer itself to arrive at once.
    offer = "    return new Promise((resolve, reject) => { settleOffer = {resolve, reject}; });"
    assert prelude.count(offer) == 1
    if step != "ice_config":
        prelude = prelude.replace(offer, "    return Promise.resolve({type: 'offer', sdp: 'v=0'});")
    return "let held = null;\n" + prelude


@pytest.mark.parametrize("late", ["resolve", "reject"])
@pytest.mark.parametrize("step", sorted(_HELD_STEP_STUBS))
def test_every_held_step_is_bounded_by_the_deadline(step: str, late: str) -> None:
    _run(_held_prelude(step) + _flow() + f"""
(async () => {{
  const flow = _runAutoPairFlow({{daemon_fingerprint: 'fp', pair_token: 't', ws_url: 'wss://x/y'}});
  let rejection = null;
  flow.catch((error) => {{ rejection = error; }});
  for (let i = 0; i < 40 && !held; i++) await tick();
  assert.ok(held, 'the flow must reach the held step');
  assert.equal(state.autopair_diagnostics.phase, '{_HELD_STAGE[step]}');
  assert.ok(fireTimer(90000), 'a pairing deadline must exist while the step is held');
  for (let i = 0; i < 20 && !rejection; i++) await tick();
  assert.ok(rejection, 'a held step must not leave the flow pending');
  assert.match(String(rejection.message), /{_HELD_STAGE[step]}/);
  const timedOut = statuses[statuses.length - 1];
  assert.equal(timedOut[1], 'timed out');
  for (const pc of connections) assert.equal(pc.closed, true, 'the connection must be released');
  assert.equal(timers.size, 0, 'no pairing timer may outlive the settled flow');
  if ('{late}' === 'resolve') held.resolve();
  else held.reject(new Error('InvalidStateError: released after the deadline'));
  for (let i = 0; i < 40; i++) await tick();
  assert.deepEqual(statuses[statuses.length - 1], timedOut,
    'a late result must not replace the timed-out status');
  assert.equal(sockets.length, 0, 'a settled flow must never open signaling');
  assert.equal(state.autopair_diagnostics.phase, 'failed');
}})().catch((error) => {{ console.error(error); process.exitCode = 1; }});
""")
