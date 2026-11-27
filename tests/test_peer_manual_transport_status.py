"""A connection-state update must never replace an instruction the user still has to act on.

The manual browser-to-browser link shows one line that tells the user what to
do next ("Complete answer ready. Send this one local signal back.") and the
browser also reports connection state at moments of its own choosing. Both
used to be written to the same element from independent asynchronous sources.
Measured in the live Firefox lane: "connecting" normally landed 2 to 4 ms
before the instruction; under load it landed after, and the user was left
looking at "WebRTC: connecting" with a signal they were never told to send.
One run in twenty failed on exactly that.

These tests execute the shipped wiring from peer.html in Node. The stubbed
signalling functions report a state change AFTER their result is ready, which
is the order that used to lose the instruction.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _wiring() -> str:
    source = (ROOT / "src" / "one_link" / "web" / "peer.html").read_text(encoding="utf-8")
    first = source.index("// ── WebRTC UI wiring")
    return source[first:source.index("// peer-ui module:", first)]


def _run(script: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to execute the shipped page wiring")
    # UTF-8 explicitly: the shipped wiring contains characters the Windows
    # default code page cannot encode.
    result = subprocess.run(
        [node, "--input-type=commonjs"], input=script, text=True, encoding="utf-8",
        capture_output=True, timeout=20, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


_PRELUDE = r"""
const assert = require('node:assert/strict');
const elements = new Map();
const element = (id) => {
  if (!elements.has(id)) {
    elements.set(id, {id, textContent: '', value: '', disabled: false, handlers: {},
      addEventListener(type, fn) { this.handlers[type] = fn; }, focus() {}, select() {}});
  }
  return elements.get(id);
};
const $ = (selector) => element(selector);
const text = (el, value) => { if (el) el.textContent = value; };
const show = () => {};
const assertWebRtcAvailable = () => {};
const encodeSignal = (signal) => JSON.stringify(signal);
const decodeSignal = (value) => JSON.parse(value);
const navigator = {clipboard: {writeText: async () => {}}};
// Each stub hands back its result first and reports a state change later,
// from a separate task: the order that used to overwrite the instruction.
let lateState = null;
const settleLater = (opts, label) => { lateState = () => opts.onState(label, {}); };
const createOfferSignal = async (opts) => {
  opts.onState('new', {});
  settleLater(opts, 'connecting');
  return {session: {id: 'offer'}, signal: {type: 'offer'}, ice_complete: true};
};
const acceptOfferSignal = async (signal, opts) => {
  opts.onState('ice:checking', {});
  settleLater(opts, 'connecting');
  return {session: {id: 'answer'}, signal: {type: 'answer'}, ice_complete: true};
};
const acceptAnswerSignal = async () => {};
const addIceSignal = async () => {};
const click = (id) => element(id).handlers.click();
"""


def test_a_late_state_update_does_not_replace_the_answer_instruction():
    _run(_PRELUDE + _wiring() + r"""
(async () => {
  element('#webrtc-remote').value = JSON.stringify({type: 'offer'});
  await click('#btn-webrtc-accept');
  const instruction = 'Complete answer ready. Send this one local signal back.';
  assert.equal(element('#webrtc-status').textContent, instruction);
  assert.equal(element('#webrtc-link-state').textContent, 'WebRTC: ice:checking');
  lateState();  // the browser reports "connecting" after the signal was ready
  assert.equal(element('#webrtc-status').textContent, instruction,
    'a state update replaced the instruction the user still has to act on');
  assert.equal(element('#webrtc-link-state').textContent, 'WebRTC: connecting');
  assert.equal(element('#webrtc-local').value, JSON.stringify({type: 'answer'}));
})().catch((error) => { console.error(error); process.exit(1); });
""")


def test_a_late_state_update_does_not_replace_the_offer_instruction():
    _run(_PRELUDE + _wiring() + r"""
(async () => {
  await click('#btn-webrtc-offer');
  const instruction = 'Complete offer ready. Send this one local signal to the other peer.';
  assert.equal(element('#webrtc-status').textContent, instruction);
  lateState();
  assert.equal(element('#webrtc-status').textContent, instruction);
  assert.equal(element('#webrtc-link-state').textContent, 'WebRTC: connecting');
})().catch((error) => { console.error(error); process.exit(1); });
""")


def test_the_page_has_a_separate_element_for_connection_state():
    page = (ROOT / "src" / "one_link" / "web" / "peer.html").read_text(encoding="utf-8")
    assert page.count('id="webrtc-status"') == 1
    assert page.count('id="webrtc-link-state"') == 1
    assert page.index('id="webrtc-status"') < page.index('id="webrtc-link-state"')
