"use strict";

// A browser-like VM for the shipped call driver: the same stubs as
// tests/test_call_ui_media.py's runtime harness (fake tracks, streams,
// RTCPeerConnection, DOM and fetch), plus a log of every DOM class removal
// and media-track stop so tests can observe teardown. The driver is the
// second inline <script> of the generated owner page (ONE_LINK_OWNER_HTML
// overrides the page, e.g. to run the same checks against an older build).
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const DEFAULT_PAGE = path.resolve(__dirname, "../../src/one_link/web/index.html");

function callDriverSource(htmlPath = process.env.ONE_LINK_OWNER_HTML || DEFAULT_PAGE) {
  const html = fs.readFileSync(htmlPath, "utf8");
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  const driver = scripts.find((code) => code.includes("call UI driver."));
  if (!driver) throw new Error(`no call driver script in ${htmlPath}`);
  return driver;
}

function createCallDriver({ window: extraWindow = {}, htmlPath } = {}) {
  const log = [];
  class FakeTrack {
    constructor(kind) { this.kind = kind; this.enabled = true; this.readyState = "live"; }
    stop() { this.readyState = "ended"; log.push(["track.stop", this.kind]); }
  }
  class FakeStream {
    constructor() { this._tracks = [new FakeTrack("audio"), new FakeTrack("video")]; }
    getTracks() { return this._tracks.slice(); }
    getAudioTracks() { return this._tracks.filter((t) => t.kind === "audio"); }
    getVideoTracks() { return this._tracks.filter((t) => t.kind === "video"); }
    addTrack(track) { if (!this._tracks.includes(track)) this._tracks.push(track); }
    removeTrack(track) { this._tracks = this._tracks.filter((t) => t !== track); }
  }
  const elements = new Map();
  function el(selector) {
    if (!elements.has(selector)) {
      const node = {
        selector,
        _src: null,
        get srcObject() { return this._src; },
        set srcObject(value) { this._src = value; if (value === null) log.push(["srcObject=null", selector]); },
        textContent: "",
        innerHTML: "",
        value: "",
        disabled: false,
        hidden: false,
        style: {},
        dataset: {},
        classList: {
          add: (...names) => log.push(["class.add", selector, ...names]),
          remove: (...names) => log.push(["class.remove", selector, ...names]),
          toggle: () => {},
          contains: () => false,
        },
        setAttribute() {},
        removeAttribute() {},
        addEventListener() {},
        removeEventListener() {},
        appendChild() {},
        remove() {},
        querySelector() { return null; },
        querySelectorAll() { return []; },
        play() { return Promise.resolve(); },
        pause() {},
        closest() { return null; },
        focus() {},
      };
      elements.set(selector, node);
    }
    return elements.get(selector);
  }
  const connections = [];
  const requests = [];
  class FakeRTCPeerConnection {
    constructor() {
      this.signalingState = "stable";
      this.iceConnectionState = "new";
      this.iceGatheringState = "new";
      this.connectionState = "new";
      this.localDescription = null;
      this.remoteDescription = null;
      this._senders = [];
      this.closed = false;
      connections.push(this);
    }
    setConfiguration() {}
    addTrack(track, stream) { this._senders.push({ track, stream }); return this._senders.at(-1); }
    addTransceiver() { return {}; }
    getTransceivers() { return []; }
    getSenders() { return this._senders.slice(); }
    getReceivers() { return []; }
    async createOffer() { return { type: "offer", sdp: "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" }; }
    async createAnswer() { return { type: "answer", sdp: "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" }; }
    async setLocalDescription(desc) { this.localDescription = desc; }
    async setRemoteDescription(desc) { this.remoteDescription = desc; }
    async addIceCandidate() {}
    async getStats() { return new Map(); }
    close() { this.closed = true; this.signalingState = "closed"; log.push(["pc.close"]); }
  }
  const errors = [];
  const context = {
    console: { ...console, error: (...args) => { errors.push(args.map(String).join(" ")); } },
    Map, Set, Promise, Date, Array, Error, Object, JSON, Math, Number, String, Proxy, Reflect, Symbol,
    Element: function Element() {},
    MediaStream: FakeStream,
    MediaRecorder: function MediaRecorder() { this.start = () => {}; this.stop = () => {}; },
    RTCPeerConnection: FakeRTCPeerConnection,
    setInterval() { return 1; },
    clearInterval() {},
    setTimeout() { return 1; },
    clearTimeout() {},
    crypto: { subtle: { async digest() { return new ArrayBuffer(32); } } },
    Blob: function Blob() { this.arrayBuffer = async () => new ArrayBuffer(0); },
    _callPermissionPreflight: async () => true,
    startCallRingback() {},
    startCallRingtone() {},
    stopCallRing() { log.push(["stopCallRing"]); },
    fetch: async (url, opts) => {
      const body = opts && opts.body ? JSON.parse(opts.body) : {};
      requests.push({ url: String(url || ""), body });
      return {
        ok: true,
        json: async () => {
          if (body.action === "initiate") return { ok: true, call_id: "call-out-1" };
          return { ok: true, call_id: body.call_id || "call-out-1", iceServers: [] };
        },
      };
    },
    document: {
      querySelector: el,
      querySelectorAll: () => [],
      getElementById: (id) => el("#" + id),
      createElement: () => el("created-" + Math.random()),
      body: el("body"),
      addEventListener() {},
      visibilityState: "visible",
    },
    navigator: {
      permissions: { query: async () => ({ state: "granted" }) },
      mediaDevices: { getUserMedia: async () => new FakeStream(), enumerateDevices: async () => [] },
    },
    localStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
    ...extraWindow,
  };
  context.window = context;
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(callDriverSource(htmlPath), context, { timeout: 2000, filename: "call-driver.js" });
  const settle = async (turns = 20) => { for (let i = 0; i < turns; i++) await new Promise((r) => setImmediate(r)); };
  return { window: context, log, errors, connections, requests, settle, el };
}

module.exports = { createCallDriver, callDriverSource };
