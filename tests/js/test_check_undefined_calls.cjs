"use strict";

// The undefined-call gate resolves names per script block, lexically. A
// name declared inside one block's IIFE is not callable from another block
// (the MNT-03 call-driver defect); a script-level declaration, a name
// published on the global object, a browser global, or a call behind a
// `typeof name === "function"` probe is.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { spawnSync } = require("node:child_process");

const checker = path.join(__dirname, "check_undefined_calls.js");

function check(blocks) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "one-link-undefined-calls-"));
  const file = path.join(dir, "page.html");
  fs.writeFileSync(file, blocks.map((b) => `<script>\n${b}\n</script>\n`).join(""), "utf8");
  try {
    const result = spawnSync(process.execPath, [checker, file], { encoding: "utf8" });
    return { status: result.status, output: result.stdout + result.stderr };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const owner = "(() => {\n  const api = { post() {} };\n  function toast() {}\n  function published() {}\n  window.published = published;\n})();";

test("a call into another block's closure is reported, as call or as receiver", () => {
  const result = check([owner, "(function () {\n  function f() { toast('x'); api.post('/x'); }\n})();"]);
  assert.equal(result.status, 1, result.output);
  assert.match(result.output, /toast\(\.\.\.\)/);
  assert.match(result.output, /api\.…\(\.\.\.\)/);
});

test("published globals, script-level declarations, browser globals and typeof probes resolve", () => {
  const result = check([
    owner + "\nfunction scriptLevel() {}",
    "(function () {\n  function f() {\n    published(); scriptLevel(); setTimeout(() => {}, 1); JSON.stringify({});\n" +
    "    if (typeof toast === 'function') toast('x');\n    typeof later === 'function' && later();\n" +
    "    const x = typeof maybe !== 'undefined' ? maybe() : null;\n  }\n})();",
  ]);
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /no undefined call sites/);
});

test("a local declaration does not leak out of its function", () => {
  const result = check(["(() => {\n  function a() { function inner() {} }\n  function b() { inner(); }\n})();"]);
  assert.equal(result.status, 1, result.output);
  assert.match(result.output, /inner\(\.\.\.\)/);
});

test("the shipped owner and peer pages have no undefined call sites", () => {
  for (const page of ["index.html", "peer.html"]) {
    const file = path.resolve(__dirname, "../../src/one_link/web", page);
    const result = spawnSync(process.execPath, [checker, file], { encoding: "utf8" });
    assert.equal(result.status, 0, page + "\n" + result.stdout + result.stderr);
  }
});
