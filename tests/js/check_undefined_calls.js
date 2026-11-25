// 2026-05-22 audit T2-M: proper undefined-call scope analyzer for
// the daemon UI's inline JS. Replaces the prior regex-based static
// check (which produced 58 false positives on object-literal
// shorthand methods, IIFEs, etc.).
//
// Strategy:
//   1. Parse each <script> block from index.html with ``acorn``.
//   2. Walk every CallExpression whose callee is a bare Identifier
//      (i.e. ``foo()`` and NOT ``a.b()`` / ``a[b]()``).
//   3. Resolve the identifier against the lexical scope chain:
//        * function / class / let / const / var declarations (incl
//          hoisting for var + function decls)
//        * function parameters (incl rest + defaults)
//        * arrow-function parameters
//        * catch-clause parameter
//        * object-pattern + array-pattern destructuring
//        * for-let / for-const / for-of / for-in
//        * import bindings
//   4. Bail out cleanly on identifiers in our allowlist of browser
//      / JS / library globals.
//   5. Report any unresolved bare-identifier calls as ``failures``.
//
// Run: ``node check_undefined_calls.js path/to/index.html``
// Exit code 0 if clean, 1 if failures, 2 on usage error.

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const acorn = require("acorn");
const walk = require("acorn-walk");

if (process.argv.length < 3) {
  console.error("usage: node check_undefined_calls.js <html-path>");
  process.exit(2);
}

const htmlPath = process.argv[2];
const html = fs.readFileSync(htmlPath, "utf8");

// Conservative allowlist of browser + JS + library globals. Goal
// is "no false positives on currently-working code"; expand as
// needed.
const GLOBALS = new Set([
  // Core JS
  "Array", "Object", "String", "Number", "Boolean", "Math", "Date",
  "JSON", "Map", "Set", "WeakMap", "WeakSet", "Symbol", "Promise",
  "RegExp", "Error", "TypeError", "ReferenceError", "RangeError",
  "SyntaxError", "URIError", "EvalError",
  "Proxy", "Reflect", "URLSearchParams", "URL", "FormData",
  "Blob", "File", "FileReader", "Image", "TextEncoder", "TextDecoder",
  "Uint8Array", "Int8Array", "Uint16Array", "Int16Array",
  "Uint32Array", "Int32Array", "Float32Array", "Float64Array",
  "Uint8ClampedArray", "BigUint64Array", "BigInt64Array",
  "ArrayBuffer", "DataView", "BigInt", "Intl", "WeakRef",
  "FinalizationRegistry", "Iterator", "Generator", "AsyncGenerator",
  // Browser globals
  "window", "document", "navigator", "location", "history",
  "console", "setTimeout", "clearTimeout", "setInterval",
  "clearInterval", "requestAnimationFrame", "cancelAnimationFrame",
  "requestIdleCallback", "cancelIdleCallback",
  "queueMicrotask", "fetch", "atob", "btoa", "structuredClone",
  "performance", "crypto", "alert", "confirm", "prompt",
  "addEventListener", "removeEventListener", "getComputedStyle",
  "matchMedia", "scrollTo", "scrollBy", "scroll", "open", "close",
  "focus", "blur", "print", "stop",
  "localStorage", "sessionStorage", "indexedDB", "caches",
  "screen", "screenLeft", "screenTop", "screenX", "screenY",
  "innerWidth", "innerHeight", "outerWidth", "outerHeight",
  "devicePixelRatio", "pageXOffset", "pageYOffset",
  "scrollX", "scrollY",
  "self", "parent", "top", "globalThis", "frames", "length",
  "Audio", "Worker", "SharedWorker", "Notification",
  "ServiceWorker", "ServiceWorkerRegistration",
  // DOM constructors
  "Event", "CustomEvent", "UIEvent", "MouseEvent", "KeyboardEvent",
  "FocusEvent", "InputEvent", "WheelEvent", "TouchEvent",
  "PointerEvent", "DragEvent", "ClipboardEvent",
  "MessageChannel", "MessageEvent", "MessagePort",
  "BroadcastChannel", "AbortController", "AbortSignal",
  "Headers", "Request", "Response", "ReadableStream", "WritableStream",
  "TransformStream", "ReadableStreamDefaultReader",
  "MutationObserver", "ResizeObserver", "IntersectionObserver",
  "PerformanceObserver",
  "Node", "Element", "Text", "DocumentFragment", "Comment",
  "Range", "Selection", "TreeWalker",
  "HTMLElement", "HTMLAnchorElement", "HTMLAreaElement",
  "HTMLAudioElement", "HTMLBRElement", "HTMLBaseElement",
  "HTMLBodyElement", "HTMLButtonElement", "HTMLCanvasElement",
  "HTMLDataElement", "HTMLDataListElement", "HTMLDetailsElement",
  "HTMLDialogElement", "HTMLDivElement", "HTMLEmbedElement",
  "HTMLFieldSetElement", "HTMLFormElement", "HTMLHeadElement",
  "HTMLHeadingElement", "HTMLHRElement", "HTMLHtmlElement",
  "HTMLIFrameElement", "HTMLImageElement", "HTMLInputElement",
  "HTMLLabelElement", "HTMLLegendElement", "HTMLLIElement",
  "HTMLLinkElement", "HTMLMapElement", "HTMLMediaElement",
  "HTMLMetaElement", "HTMLMeterElement", "HTMLModElement",
  "HTMLOListElement", "HTMLObjectElement", "HTMLOptGroupElement",
  "HTMLOptionElement", "HTMLOutputElement", "HTMLParagraphElement",
  "HTMLPictureElement", "HTMLPreElement", "HTMLProgressElement",
  "HTMLQuoteElement", "HTMLScriptElement", "HTMLSelectElement",
  "HTMLSourceElement", "HTMLSpanElement", "HTMLStyleElement",
  "HTMLTableElement", "HTMLTableCellElement", "HTMLTableRowElement",
  "HTMLTextAreaElement", "HTMLTimeElement", "HTMLTitleElement",
  "HTMLTrackElement", "HTMLUListElement", "HTMLVideoElement",
  "SVGElement", "SVGSVGElement",
  "CSS", "CSSStyleSheet", "CSSStyleDeclaration",
  "WebSocket", "EventSource", "XMLHttpRequest",
  "MediaStream", "MediaStreamTrack", "MediaRecorder",
  "RTCPeerConnection", "RTCSessionDescription", "RTCIceCandidate",
  "RTCDataChannel", "RTCRtpSender", "RTCRtpReceiver",
  "RTCRtpTransceiver", "RTCDtlsTransport", "RTCIceTransport",
  "RTCStatsReport", "RTCCertificate",
  "DataTransfer", "DataTransferItem", "DataTransferItemList",
  // JS keywords / operators (acorn's CallExpression won't match
  // most of these, but ``new Foo()`` is a NewExpression we don't
  // visit; keep the safety net)
  "typeof", "instanceof", "this", "super",
  "encodeURIComponent", "decodeURIComponent",
  "encodeURI", "decodeURI",
  "isNaN", "isFinite", "parseInt", "parseFloat",
  "globalThis", "NaN", "Infinity", "undefined",
  // Things one_link's inline JS uses widely (added incrementally
  // as we discovered them — these are NOT bug-shape, they're
  // expected globals defined elsewhere in the inline tree)
  "VTTCue", "TrackEvent",
  "GamepadEvent", "DeviceMotionEvent", "DeviceOrientationEvent",
  "OffscreenCanvas", "ImageBitmap", "createImageBitmap",
  "PromiseRejectionEvent", "ErrorEvent",
  "FileSystemDirectoryHandle", "FileSystemFileHandle",
  "showDirectoryPicker", "showOpenFilePicker", "showSaveFilePicker",
  // Modern proposal globals
  "AggregateError",
  // Receivers of member calls (``WebAssembly.instantiate``,
  // ``IDBKeyRange.bound``), resolved since receivers are checked too.
  "WebAssembly", "IDBKeyRange", "IDBDatabase", "IDBTransaction",
  "IDBObjectStore", "IDBIndex", "IDBRequest", "IDBCursor",
]);

// Extract inline <script> blocks (not src=).
function extractScripts(src) {
  const out = [];
  const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(src)) !== null) {
    out.push({ index: out.length + 1, body: m[1] });
  }
  return out;
}

// All <script> blocks share the global scope. We collect every
// top-level declaration across all blocks FIRST (one global scope),
// then walk each block with that global scope as the outer frame.
class Analyzer {
  constructor(block, globalScope) {
    this.block = block;
    this.globalScope = globalScope;
    this.failures = [];
    this.guards = []; // stack of Set<name> proven callable by a typeof probe
  }

  static parse(block) {
    return acorn.parse(block.body, {
      ecmaVersion: "latest",
      sourceType: "script",
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      allowSuperOutsideMethod: true,
      allowImportExportEverywhere: true,
      allowHashBang: true,
      locations: true,
    });
  }

  // The names every block can really reach at runtime: the script-level
  // declarations of each block (the shared global lexical environment)
  // and properties published on the global object (``window.foo = ...``).
  //
  // MNT-03: this used to pool every named binding at ANY depth of every
  // block into one "soft global" scope. Each block wraps its body in an
  // IIFE, so a name declared inside one block's closure is NOT visible in
  // another block; the pooled scope hid exactly that class of defect (the
  // call driver named the owner closure's `api`, `toast`, `state` and
  // `renderMessages`, which threw ReferenceError at runtime). Resolution
  // is now lexical per block. A call guarded by ``typeof foo ===
  // "function"`` is a feature probe and is not reported when unresolved;
  // tests/js/ownership_census.js separately reports any reference to
  // another closure's top-level names, guarded or not.
  static collectTopLevel(ast, globalScope) {
    for (const stmt of ast.body) {
      switch (stmt.type) {
        case "FunctionDeclaration":
        case "ClassDeclaration":
          if (stmt.id) globalScope.add(stmt.id.name);
          break;
        case "VariableDeclaration":
          for (const d of stmt.declarations) {
            Analyzer.collectBindingTargetsStatic(d.id, globalScope);
          }
          break;
        case "ImportDeclaration":
          for (const s of stmt.specifiers) {
            if (s.local) globalScope.add(s.local.name);
          }
          break;
        default:
          break;
      }
    }
    Analyzer.collectPublishedGlobals(ast, globalScope);
  }

  static collectPublishedGlobals(ast, globalScope) {
    function visit(node) {
      if (!node || typeof node !== "object") return;
      if (Array.isArray(node)) {
        for (const c of node) visit(c);
        return;
      }
      switch (node.type) {
        case "AssignmentExpression":
          // ``window.foo = function () { ... }`` and friends —
          // anything assigned to a ``window``/``self`` property
          // becomes a true global.
          if (
            node.left
            && node.left.type === "MemberExpression"
            && node.left.object
            && node.left.object.type === "Identifier"
            && (node.left.object.name === "window"
                || node.left.object.name === "self"
                || node.left.object.name === "globalThis")
            && node.left.property
            && node.left.property.type === "Identifier"
          ) {
            globalScope.add(node.left.property.name);
          }
          break;
      }
      for (const k of Object.keys(node)) {
        if (k === "loc" || k === "start" || k === "end" || k === "type") {
          continue;
        }
        visit(node[k]);
      }
    }
    visit(ast);
  }

  static collectBindingTargetsStatic(pat, scope) {
    if (!pat) return;
    switch (pat.type) {
      case "Identifier":
        scope.add(pat.name);
        return;
      case "AssignmentPattern":
        Analyzer.collectBindingTargetsStatic(pat.left, scope);
        return;
      case "RestElement":
        Analyzer.collectBindingTargetsStatic(pat.argument, scope);
        return;
      case "ArrayPattern":
        for (const e of pat.elements) if (e) Analyzer.collectBindingTargetsStatic(e, scope);
        return;
      case "ObjectPattern":
        for (const p of pat.properties) {
          if (p.type === "RestElement") {
            Analyzer.collectBindingTargetsStatic(p.argument, scope);
          } else {
            Analyzer.collectBindingTargetsStatic(p.value, scope);
          }
        }
        return;
    }
  }

  analyze(ast) {
    // The block-local scope only adds non-top-level hoisted decls
    // that the global pre-pass already captured. We walk with
    // ``[globalScope]`` as the outer frame.
    this._walk(ast, [this.globalScope]);
  }

  // Hoist function declarations + var declarations into the
  // enclosing function/global scope. Called once per scope before
  // walking its children.
  _collectHoisted(node, scope) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const c of node) this._collectHoisted(c, scope);
      return;
    }
    switch (node.type) {
      case "FunctionDeclaration":
        if (node.id) scope.add(node.id.name);
        return; // do not recurse into the function body
      case "VariableDeclaration":
        if (node.kind === "var") {
          for (const d of node.declarations) {
            this._collectBindingTargets(d.id, scope);
          }
        }
        // let / const are NOT hoisted to var scope; they belong
        // to the block-scope collected at walk-time.
        return;
      case "FunctionExpression":
      case "ArrowFunctionExpression":
      case "ClassDeclaration":
      case "ClassExpression":
        return; // skip — new function/class scope handles its own
      default:
        for (const k of Object.keys(node)) {
          if (k === "loc" || k === "start" || k === "end") continue;
          this._collectHoisted(node[k], scope);
        }
    }
  }

  _collectBindingTargets(pat, scope) {
    if (!pat) return;
    switch (pat.type) {
      case "Identifier":
        scope.add(pat.name);
        return;
      case "AssignmentPattern":
        this._collectBindingTargets(pat.left, scope);
        return;
      case "RestElement":
        this._collectBindingTargets(pat.argument, scope);
        return;
      case "ArrayPattern":
        for (const e of pat.elements) if (e) this._collectBindingTargets(e, scope);
        return;
      case "ObjectPattern":
        for (const p of pat.properties) {
          if (p.type === "RestElement") {
            this._collectBindingTargets(p.argument, scope);
          } else {
            this._collectBindingTargets(p.value, scope);
          }
        }
        return;
      default:
        return;
    }
  }

  _walk(node, scopes) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const c of node) this._walk(c, scopes);
      return;
    }
    const cur = scopes[scopes.length - 1];

    switch (node.type) {
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression": {
        // Function name (named fn expr) visible inside the body.
        const fnScope = new Set();
        if (node.id && node.type === "FunctionExpression") {
          fnScope.add(node.id.name);
        }
        for (const p of node.params) {
          this._collectBindingTargets(p, fnScope);
        }
        scopes.push(fnScope);
        this._collectHoisted(node.body, fnScope);
        this._walk(node.body, scopes);
        scopes.pop();
        return;
      }
      case "ClassDeclaration":
      case "ClassExpression": {
        if (node.id) cur.add(node.id.name);
        if (node.superClass) this._walk(node.superClass, scopes);
        const classScope = new Set();
        if (node.id) classScope.add(node.id.name);
        scopes.push(classScope);
        this._walk(node.body, scopes);
        scopes.pop();
        return;
      }
      case "BlockStatement": {
        // Block scope for let/const/class. var was hoisted earlier.
        const blockScope = new Set();
        for (const stmt of node.body) {
          if (stmt.type === "VariableDeclaration"
              && (stmt.kind === "let" || stmt.kind === "const")) {
            for (const d of stmt.declarations) {
              this._collectBindingTargets(d.id, blockScope);
            }
          } else if (stmt.type === "ClassDeclaration" && stmt.id) {
            blockScope.add(stmt.id.name);
          } else if (stmt.type === "FunctionDeclaration" && stmt.id) {
            blockScope.add(stmt.id.name);
          }
        }
        scopes.push(blockScope);
        for (const stmt of node.body) this._walk(stmt, scopes);
        scopes.pop();
        return;
      }
      case "ForStatement":
      case "ForInStatement":
      case "ForOfStatement": {
        const forScope = new Set();
        if (node.init && node.init.type === "VariableDeclaration") {
          for (const d of node.init.declarations) {
            this._collectBindingTargets(d.id, forScope);
          }
        } else if (
          (node.left && node.left.type === "VariableDeclaration")
        ) {
          for (const d of node.left.declarations) {
            this._collectBindingTargets(d.id, forScope);
          }
        }
        scopes.push(forScope);
        if (node.init) this._walk(node.init, scopes);
        if (node.left) this._walk(node.left, scopes);
        if (node.right) this._walk(node.right, scopes);
        if (node.test) this._walk(node.test, scopes);
        if (node.update) this._walk(node.update, scopes);
        if (node.body) this._walk(node.body, scopes);
        scopes.pop();
        return;
      }
      case "CatchClause": {
        const catchScope = new Set();
        if (node.param) this._collectBindingTargets(node.param, catchScope);
        scopes.push(catchScope);
        this._walk(node.body, scopes);
        scopes.pop();
        return;
      }
      case "VariableDeclaration": {
        for (const d of node.declarations) {
          this._collectBindingTargets(d.id, cur);
          if (d.init) this._walk(d.init, scopes);
        }
        return;
      }
      case "ImportDeclaration":
        for (const s of node.specifiers) {
          if (s.local) cur.add(s.local.name);
        }
        return;
      case "MemberExpression":
        // ``a.b()`` — we only walk the object side; the property
        // is not a free identifier. If computed (``a[expr]``), walk
        // expr as a normal node.
        this._walk(node.object, scopes);
        if (node.computed) this._walk(node.property, scopes);
        return;
      case "Property":
        // ``{ foo: bar }`` — ``foo`` is a key, NOT a referenced
        // identifier (unless computed); ``bar`` is.
        if (node.computed) this._walk(node.key, scopes);
        this._walk(node.value, scopes);
        return;
      case "MethodDefinition":
        if (node.computed) this._walk(node.key, scopes);
        this._walk(node.value, scopes);
        return;
      case "IfStatement":
      case "ConditionalExpression": {
        // ``if (typeof foo === "function") foo()`` probes for foo.
        this._walk(node.test, scopes);
        const probed = Analyzer.typeofProbes(node.test);
        this.guards.push(probed);
        this._walk(node.consequent, scopes);
        this.guards.pop();
        this._walk(node.alternate, scopes);
        return;
      }
      case "LogicalExpression": {
        this._walk(node.left, scopes);
        if (node.operator === "&&") {
          this.guards.push(Analyzer.typeofProbes(node.left));
          this._walk(node.right, scopes);
          this.guards.pop();
        } else {
          this._walk(node.right, scopes);
        }
        return;
      }
      case "CallExpression": {
        // ★ The check we care about.
        const callee = node.callee;
        if (callee.type === "Identifier") {
          const name = callee.name;
          const probed = this.guards.some((g) => g.has(name));
          if (!GLOBALS.has(name) && !probed && !this._resolved(name, scopes)) {
            this.failures.push({
              name,
              line: callee.loc ? callee.loc.start.line : null,
              column: callee.loc ? callee.loc.start.column : null,
              block: this.block.index,
            });
          }
        }
        // ``foo.bar()`` on a receiver that resolves nowhere throws the
        // same ReferenceError (the call driver's ``api.post`` did).
        let root = callee;
        while (root && root.type === "MemberExpression") root = root.object;
        if (root && root !== callee && root.type === "Identifier") {
          const name = root.name;
          const probed = this.guards.some((g) => g.has(name));
          if (!GLOBALS.has(name) && !probed && !this._resolved(name, scopes)) {
            this.failures.push({
              name: `${name}.…`,
              line: root.loc ? root.loc.start.line : null,
              column: root.loc ? root.loc.start.column : null,
              block: this.block.index,
            });
          }
        }
        // Walk children: callee (so a.b.c.foo() walks a, b, c),
        // arguments, etc.
        this._walk(node.callee, scopes);
        for (const a of node.arguments) this._walk(a, scopes);
        return;
      }
      case "LabeledStatement":
        // Labels aren't variables; just walk the body.
        this._walk(node.body, scopes);
        return;
      default:
        for (const k of Object.keys(node)) {
          if (k === "loc" || k === "start" || k === "end" || k === "type") {
            continue;
          }
          this._walk(node[k], scopes);
        }
    }
  }

  // Names a condition proves callable: ``typeof foo === "function"`` or
  // ``typeof foo !== "undefined"`` (either operand order), possibly joined
  // with other conditions by ``&&``.
  static typeofProbes(test, out = new Set()) {
    if (!test) return out;
    if (test.type === "LogicalExpression" && test.operator === "&&") {
      Analyzer.typeofProbes(test.left, out);
      Analyzer.typeofProbes(test.right, out);
      return out;
    }
    if (test.type !== "BinaryExpression") return out;
    const positive = test.operator === "===" || test.operator === "==";
    const negative = test.operator === "!==" || test.operator === "!=";
    if (!positive && !negative) return out;
    for (const [a, b] of [[test.left, test.right], [test.right, test.left]]) {
      if (a.type === "UnaryExpression" && a.operator === "typeof"
          && a.argument.type === "Identifier" && b.type === "Literal") {
        if ((positive && b.value === "function") || (negative && b.value === "undefined")) {
          out.add(a.argument.name);
        }
      }
    }
    return out;
  }

  _resolved(name, scopes) {
    for (let i = scopes.length - 1; i >= 0; i--) {
      if (scopes[i].has(name)) return true;
    }
    return false;
  }
}

let exitCode = 0;
const scripts = extractScripts(html);
const allFailures = [];

// Pass 1: parse every block once, collect ASTs + populate the
// shared global scope from top-level decls.
const globalScope = new Set();
const parsed = [];
for (const s of scripts) {
  try {
    const ast = Analyzer.parse(s);
    parsed.push({ s, ast });
    Analyzer.collectTopLevel(ast, globalScope);
  } catch (e) {
    console.error(
      `parse error in script #${s.index}: ${e.message}`
    );
    exitCode = 1;
  }
}

// Pass 2: walk each block with the unified global scope so
// cross-block calls resolve correctly.
for (const { s, ast } of parsed) {
  const a = new Analyzer(s, globalScope);
  try {
    a.analyze(ast);
  } catch (e) {
    console.error(
      `walk error in script #${s.index}: ${e.message}`
    );
    exitCode = 1;
    continue;
  }
  for (const f of a.failures) {
    allFailures.push(f);
  }
}

if (allFailures.length > 0) {
  console.error(
    `T2-M undefined-call check found ${allFailures.length} site(s):`
  );
  for (const f of allFailures.slice(0, 30)) {
    console.error(
      `  script #${f.block} line ${f.line ?? "?"}: ${f.name}(...)`
    );
  }
  if (allFailures.length > 30) {
    console.error(`  ... (${allFailures.length - 30} more)`);
  }
  exitCode = 1;
}

if (exitCode === 0) {
  const total = scripts.reduce((acc, s) => acc + s.body.length, 0);
  console.log(
    `T2-M ok: ${scripts.length} inline script block(s), `
    + `${total} bytes — no undefined call sites.`
  );
}

process.exit(exitCode);
