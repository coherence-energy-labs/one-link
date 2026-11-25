// MNT-03 ownership census for the shipped browser closures.
//
// The owner and peer pages are assembled by scripts/build_owner_ui.py from
// ordered feature modules that still share one lexical closure per lifecycle
// (owner, calls, peer). Sharing a closure lets any module assign or mutate a
// binding another module declared. This tool makes that coupling measurable:
// for every top-level binding of every shipped closure it reports the
// declaring module and every OTHER module that writes it.
//
// It analyzes the generated HTML, not the sources: what is measured is what
// ships. Module boundaries come from the builder's
// "// <page>-ui module: <path>" markers, and the builder's --check gate keeps
// the HTML equal to the canonical sources.
//
// A write is any of:
//   assign    the binding itself is the target of =, op=, &&=, ||=, ??=, a
//             destructuring pattern, or a for-in/for-of head
//   update    ++/-- on the binding
//   property  a member chain rooted at the binding is assigned, updated,
//             deleted, destructured into, or used as a for-in/for-of head
//   mutator   a member chain rooted at the binding calls a built-in mutator
//             (Array/Map/Set/WeakMap/WeakSet), or the chain is the target of
//             Object.assign/defineProperty/defineProperties/setPrototypeOf
//             or Reflect.set/defineProperty/deleteProperty/setPrototypeOf
//
// A chain is "rooted at" a binding when, walking down member objects and the
// receivers of view calls (get, at, find, findLast, values, entries, keys),
// it reaches an identifier that resolves lexically to the binding. Local
// aliases are followed transitively: a local initialized or assigned from a
// rooted chain (directly, through ?:, ||, &&, ?? or object destructuring),
// a for-of variable iterating a rooted chain, and the element parameter of a
// forEach/find/findLast/filter/some/every/map/flatMap/reduce callback on a
// rooted chain. Identifier resolution is a real scope analysis (hoisting,
// block scopes, parameters, catch clauses, class and function names), so a
// local that shadows a top-level name is never confused with it.
//
// One exemption is structural, not a judgement: a binding initialized
// directly from a service factory (`const x = createY(...)`, where createY is
// declared in the services scope) holds that service's interface. A
// depth-one method call on it (`x.clear()`) is a call through the interface
// and is not a mutator write. Deeper chains (`x.items.push()`) and every
// property write through it are still writes.
//
// Not followed (stated so the census is not read as stronger than it is):
// values passed into other functions as arguments (interprocedural flow),
// values returned from functions, copies made by slice/filter/map/concat and
// then mutated, aliases stored into object fields, and dynamic code. Each
// one is a way to write shared state the census cannot see; review is the
// control for them.
//
// Usage:
//   node ownership_census.js                 summary for the shipped pages
//   node ownership_census.js --json          full census as JSON
//   node ownership_census.js --check         compare to the committed baseline
//   node ownership_census.js --write-baseline   refresh counts, keep rationales
//
// Exit codes: 0 ok, 1 baseline mismatch, 2 usage or parse failure.

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const acorn = require("acorn");

const ROOT = path.resolve(__dirname, "../..");
const DEFAULT_PAGES = {
  owner: path.join(ROOT, "src/one_link/web/index.html"),
  peer: path.join(ROOT, "src/one_link/web/peer.html"),
};
const BASELINE_PATH = path.join(__dirname, "ownership_baseline.json");

const ARRAY_MUTATORS = ["push", "pop", "shift", "unshift", "splice", "sort", "reverse", "fill", "copyWithin"];
const COLLECTION_MUTATORS = ["set", "add", "delete", "clear"];
const MUTATORS = new Set([...ARRAY_MUTATORS, ...COLLECTION_MUTATORS]);
const VIEW_CALLS = new Set(["get", "at", "find", "findLast", "values", "entries", "keys"]);
const ELEMENT_CALLBACKS = new Set(["forEach", "find", "findLast", "filter", "some", "every", "map", "flatMap"]);
const REDUCE_CALLBACKS = new Set(["reduce", "reduceRight"]);
const OBJECT_TARGET_WRITERS = new Set(["assign", "defineProperty", "defineProperties", "setPrototypeOf"]);
const REFLECT_TARGET_WRITERS = new Set(["set", "defineProperty", "deleteProperty", "setPrototypeOf"]);
const GLOBAL_OBJECTS = new Set(["window", "globalThis", "self"]);

class CensusError extends Error {}

// ── Scope analysis ──────────────────────────────────────────────────────────

class Scope {
  constructor(kind, parent, node) {
    this.kind = kind; // "global" | "function" | "block" | "catch" | "class" | "name"
    this.parent = parent;
    this.node = node;
    this.vars = new Map();
    this.functionScope = kind === "function" || kind === "global" ? this : parent.functionScope;
  }
  declare(name, decl) {
    // Redeclaration of a var/function in one scope is the same binding.
    if (!this.vars.has(name)) this.vars.set(name, decl);
    return this.vars.get(name);
  }
  resolve(name) {
    for (let scope = this; scope; scope = scope.parent) {
      const found = scope.vars.get(name);
      if (found) return found;
    }
    return null;
  }
}

function patternIdentifiers(pattern, out = []) {
  if (!pattern) return out;
  switch (pattern.type) {
    case "Identifier": out.push(pattern); break;
    case "ObjectPattern":
      for (const prop of pattern.properties) {
        patternIdentifiers(prop.type === "RestElement" ? prop.argument : prop.value, out);
      }
      break;
    case "ArrayPattern": for (const element of pattern.elements) patternIdentifiers(element, out); break;
    case "RestElement": patternIdentifiers(pattern.argument, out); break;
    case "AssignmentPattern": patternIdentifiers(pattern.left, out); break;
    default: break; // MemberExpression targets declare nothing.
  }
  return out;
}

// Collect var-scoped names declared by statements of one function body,
// without entering nested functions or classes.
function collectVarDeclarations(node, out) {
  if (!node || typeof node.type !== "string") return;
  switch (node.type) {
    case "VariableDeclaration":
      if (node.kind === "var") for (const d of node.declarations) out.push(...patternIdentifiers(d.id).map((id) => [id, d, node]));
      return;
    case "FunctionDeclaration": case "FunctionExpression": case "ArrowFunctionExpression":
    case "ClassDeclaration": case "ClassExpression":
      return;
    case "ForStatement": collectVarDeclarations(node.init, out); collectVarDeclarations(node.body, out); return;
    case "ForInStatement": case "ForOfStatement":
      collectVarDeclarations(node.left, out); collectVarDeclarations(node.body, out); return;
    case "IfStatement": collectVarDeclarations(node.consequent, out); collectVarDeclarations(node.alternate, out); return;
    case "BlockStatement": case "Program": case "StaticBlock": for (const s of node.body) collectVarDeclarations(s, out); return;
    case "WhileStatement": case "DoWhileStatement": case "LabeledStatement": case "WithStatement":
      collectVarDeclarations(node.body, out); return;
    case "TryStatement":
      collectVarDeclarations(node.block, out);
      if (node.handler) collectVarDeclarations(node.handler.body, out);
      collectVarDeclarations(node.finalizer, out);
      return;
    case "SwitchStatement": for (const c of node.cases) for (const s of c.consequent) collectVarDeclarations(s, out); return;
    default: return;
  }
}

// ── Census ─────────────────────────────────────────────────────────────────

function moduleIndex(code, page) {
  const marker = new RegExp(`^// ${page}-ui module: ([a-z_]+/[a-z0-9_]+\\.js)$`, "gm");
  const starts = [];
  for (const match of code.matchAll(marker)) starts.push({ offset: match.index, path: match[1] });
  if (!starts.length) throw new CensusError(`no "${page}-ui module" markers: not a generated ${page} script`);
  return (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    let found = null;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (starts[mid].offset <= offset) { found = starts[mid]; lo = mid + 1; } else hi = mid - 1;
    }
    return found ? found.path : "<wrapper>";
  };
}

// 1-based line of an offset within its canonical module source (the line
// after the module marker is line 1), for reports that point at sources.
function moduleLineIndex(code, page) {
  const marker = new RegExp(`^// ${page}-ui module: [a-z_]+/[a-z0-9_]+[.]js$`, "gm");
  // A Git checkout may carry CRLF; the body starts after the marker's LF.
  const NEWLINE = String.fromCharCode(10);
  const bodyStarts = [...code.matchAll(marker)].map((m) => code.indexOf(NEWLINE, m.index) + 1);
  const newlines = [];
  for (let i = code.indexOf(NEWLINE); i >= 0; i = code.indexOf(NEWLINE, i + 1)) newlines.push(i);
  const linesBefore = (offset) => {
    let lo = 0;
    let hi = newlines.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (newlines[mid] < offset) lo = mid + 1; else hi = mid; }
    return lo;
  };
  return (offset) => {
    let start = 0;
    for (const s of bodyStarts) if (s <= offset) start = s; else break;
    return linesBefore(offset) - linesBefore(start) + 1;
  };
}

function literalPropertyName(member) {
  if (!member.computed) return member.property.type === "PrivateIdentifier" ? `#${member.property.name}` : member.property.name;
  if (member.property.type === "Literal" && (typeof member.property.value === "string" || typeof member.property.value === "number")) {
    return String(member.property.value);
  }
  return null;
}

function unwrap(node) {
  while (node && (node.type === "ChainExpression" || node.type === "ParenthesizedExpression")) node = node.expression;
  return node;
}

// Analyze one generated script. Returns bindings and writes.
function analyzeScript(code, { page, script }) {
  let ast;
  try {
    ast = acorn.parse(code, { ecmaVersion: "latest", sourceType: "script", allowHashBang: false });
  } catch (error) {
    throw new CensusError(`${page} script ${script}: parse failed: ${error.message}`);
  }
  const moduleAt = moduleIndex(code, page);
  const lineAt = moduleLineIndex(code, page);
  const strictProgram = /^\s*(?:\/\/[^\n]*\n\s*)*\(\(\) => \{\n\s*"use strict";/.test(code);

  // The builder emits: Program -> (() => { services...; (feature closure)(); })();
  const outer = ast.body.length === 1 && unwrap(ast.body[0].expression);
  const outerFn = outer && outer.type === "CallExpression" ? outer.callee : null;
  if (!outerFn || !/FunctionExpression$/.test(outerFn.type) || outerFn.body.type !== "BlockStatement") {
    throw new CensusError(`${page} script ${script}: missing the builder's private service scope`);
  }
  const featureCalls = outerFn.body.body
    .filter((s) => s.type === "ExpressionStatement" && unwrap(s.expression).type === "CallExpression")
    .map((s) => unwrap(s.expression).callee)
    .filter((fn) => /FunctionExpression$/.test(fn.type));
  if (featureCalls.length !== 1) throw new CensusError(`${page} script ${script}: expected exactly one feature closure`);
  const featureFn = featureCalls[0];

  const decls = []; // every declaration
  const references = new Map(); // Identifier node -> decl (or null for globals)
  const events = []; // write-shaped nodes, resolved after aliasing
  const guarded = new Set(); // identifiers only probed with typeof
  const scopeOfFunction = new Map();
  const factoryNames = new Set();

  function makeDecl(id, kind, scope, extra = {}) {
    const decl = {
      name: id.name, kind, scope, node: id, start: id.start,
      module: moduleAt(id.start), level: null, init: null, ...extra,
    };
    const existing = scope.declare(id.name, decl);
    if (existing === decl) decls.push(decl);
    return existing;
  }

  function hoistFunctionScope(body, scope) {
    const vars = [];
    collectVarDeclarations(body, vars);
    for (const [id, declarator] of vars) makeDecl(id, "var", scope, { init: declarator.init && declarator.id === id ? declarator.init : null });
  }

  function hoistBlock(statements, scope, strict) {
    for (const s of statements) {
      if (s.type === "VariableDeclaration" && s.kind !== "var") {
        for (const d of s.declarations) {
          for (const id of patternIdentifiers(d.id)) {
            makeDecl(id, s.kind, scope, { init: d.id === id ? d.init : null });
          }
        }
      } else if (s.type === "FunctionDeclaration" && s.id) {
        // Block functions are block-scoped in strict code; sloppy code also
        // hoists a var-like binding (Annex B). Resolution inside the block is
        // identical either way.
        makeDecl(s.id, "function", scope, { init: s });
        if (!strict && scope.kind === "block" && !scope.functionScope.vars.has(s.id.name)) {
          makeDecl(s.id, "function", scope.functionScope, { init: s });
        }
      } else if (s.type === "ClassDeclaration" && s.id) {
        makeDecl(s.id, "class", scope, { init: s });
      }
    }
  }

  function isStrictBody(body, inherited) {
    if (inherited) return true;
    for (const s of body) {
      if (s.type === "ExpressionStatement" && typeof s.directive === "string") {
        if (s.directive === "use strict") return true;
      } else break;
    }
    return false;
  }

  function visitPattern(pattern, scope, strict) {
    // Visit expressions inside a binding/assignment pattern (defaults,
    // computed keys, member targets) without treating binding names as reads.
    if (!pattern) return;
    switch (pattern.type) {
      case "Identifier": references.set(pattern, scope.resolve(pattern.name)); return;
      case "ObjectPattern":
        for (const prop of pattern.properties) {
          if (prop.type === "RestElement") { visitPattern(prop.argument, scope, strict); continue; }
          if (prop.computed) visit(prop.key, scope, strict);
          visitPattern(prop.value, scope, strict);
        }
        return;
      case "ArrayPattern": for (const e of pattern.elements) visitPattern(e, scope, strict); return;
      case "RestElement": visitPattern(pattern.argument, scope, strict); return;
      case "AssignmentPattern": visitPattern(pattern.left, scope, strict); visit(pattern.right, scope, strict); return;
      default: visit(pattern, scope, strict); return;
    }
  }

  function visitFunction(fn, scope, strict) {
    let outerScope = scope;
    if (fn.type === "FunctionExpression" && fn.id) {
      outerScope = new Scope("name", scope, fn);
      makeDecl(fn.id, "function", outerScope, { init: fn });
    }
    const fnScope = new Scope("function", outerScope, fn);
    scopeOfFunction.set(fn, fnScope);
    const bodyStrict = fn.body.type === "BlockStatement" ? isStrictBody(fn.body.body, strict) : strict;
    for (const param of fn.params) for (const id of patternIdentifiers(param)) makeDecl(id, "param", fnScope);
    if (fn.body.type === "BlockStatement") {
      hoistFunctionScope(fn.body, fnScope);
      hoistBlock(fn.body.body, fnScope, bodyStrict);
    }
    for (const param of fn.params) visitPattern(param, fnScope, bodyStrict);
    if (fn.body.type === "BlockStatement") for (const s of fn.body.body) visit(s, fnScope, bodyStrict);
    else visit(fn.body, fnScope, bodyStrict);
  }

  function visitClass(cls, scope, strict) {
    if (cls.superClass) visit(cls.superClass, scope, true);
    const classScope = new Scope("class", scope, cls);
    if (cls.id && cls.type === "ClassExpression") makeDecl(cls.id, "class", classScope, { init: cls });
    for (const member of cls.body.body) {
      if (member.type === "StaticBlock") {
        const blockScope = new Scope("function", classScope, member);
        hoistFunctionScope(member, blockScope);
        hoistBlock(member.body, blockScope, true);
        for (const s of member.body) visit(s, blockScope, true);
        continue;
      }
      if (member.computed) visit(member.key, classScope, true);
      if (member.value) {
        if (member.type === "PropertyDefinition") {
          const fieldScope = new Scope("function", classScope, member);
          visit(member.value, fieldScope, true);
        } else visit(member.value, classScope, true);
      }
    }
  }

  function visit(node, scope, strict) {
    if (!node || typeof node.type !== "string") return;
    switch (node.type) {
      case "Identifier":
        references.set(node, scope.resolve(node.name));
        return;
      case "FunctionDeclaration":
        visitFunction(node, scope, strict);
        return;
      case "FunctionExpression": case "ArrowFunctionExpression":
        visitFunction(node, scope, strict);
        return;
      case "ClassDeclaration": case "ClassExpression":
        visitClass(node, scope, strict);
        return;
      case "BlockStatement": {
        const block = new Scope("block", scope, node);
        hoistBlock(node.body, block, strict);
        for (const s of node.body) visit(s, block, strict);
        return;
      }
      case "StaticBlock": return;
      case "SwitchStatement": {
        visit(node.discriminant, scope, strict);
        const block = new Scope("block", scope, node);
        hoistBlock(node.cases.flatMap((c) => c.consequent), block, strict);
        for (const c of node.cases) { visit(c.test, block, strict); for (const s of c.consequent) visit(s, block, strict); }
        return;
      }
      case "ForStatement": case "ForInStatement": case "ForOfStatement": {
        const loop = new Scope("block", scope, node);
        const head = node.type === "ForStatement" ? node.init : node.left;
        if (head && head.type === "VariableDeclaration" && head.kind !== "var") hoistBlock([head], loop, strict);
        if (node.type === "ForStatement") {
          visit(node.init, loop, strict); visit(node.test, loop, strict); visit(node.update, loop, strict);
        } else {
          visit(node.right, loop, strict);
          if (node.left.type === "VariableDeclaration") {
            for (const d of node.left.declarations) visitPattern(d.id, loop, strict);
          } else visitPattern(node.left, loop, strict);
          events.push({ type: "forHead", node, scope: loop });
        }
        visit(node.body, loop, strict);
        return;
      }
      case "CatchClause": {
        const catchScope = new Scope("catch", scope, node);
        if (node.param) for (const id of patternIdentifiers(node.param)) makeDecl(id, "catch", catchScope);
        if (node.param) visitPattern(node.param, catchScope, strict);
        visit(node.body, catchScope, strict);
        return;
      }
      case "VariableDeclaration":
        for (const d of node.declarations) {
          visitPattern(d.id, scope, strict);
          visit(d.init, scope, strict);
          if (d.init) events.push({ type: "declare", node: d, scope });
        }
        return;
      case "MemberExpression":
        visit(node.object, scope, strict);
        if (node.computed) visit(node.property, scope, strict);
        return;
      case "Property":
        if (node.computed) visit(node.key, scope, strict);
        visit(node.value, scope, strict);
        return;
      case "MethodDefinition": case "PropertyDefinition":
        if (node.computed) visit(node.key, scope, strict);
        visit(node.value, scope, strict);
        return;
      case "LabeledStatement": visit(node.body, scope, strict); return;
      case "BreakStatement": case "ContinueStatement": case "MetaProperty": case "PrivateIdentifier":
      case "Literal": case "ThisExpression": case "Super": case "TemplateElement": case "DebuggerStatement":
      case "EmptyStatement":
        return;
      case "AssignmentExpression":
        visitPattern(node.left, scope, strict);
        visit(node.right, scope, strict);
        events.push({ type: "assign", node, scope });
        return;
      case "UpdateExpression":
        visit(node.argument, scope, strict);
        events.push({ type: "update", node, scope });
        return;
      case "UnaryExpression":
        // `typeof name` never throws for an unresolvable name; it is a
        // feature probe, not a use.
        if (node.operator === "typeof" && node.argument.type === "Identifier") guarded.add(node.argument);
        visit(node.argument, scope, strict);
        if (node.operator === "delete") events.push({ type: "delete", node, scope });
        return;
      case "CallExpression": case "NewExpression":
        visit(node.callee, scope, strict);
        for (const a of node.arguments) visit(a, scope, strict);
        if (node.type === "CallExpression") events.push({ type: "call", node, scope });
        return;
      default:
        for (const key of Object.keys(node)) {
          if (key === "type" || key === "start" || key === "end" || key === "loc" || key === "range") continue;
          const value = node[key];
          if (Array.isArray(value)) { for (const v of value) if (v && typeof v.type === "string") visit(v, scope, strict); }
          else if (value && typeof value.type === "string") visit(value, scope, strict);
        }
    }
  }

  // Program-level scope, then the services scope and the feature closure.
  const globalScope = new Scope("global", null, ast);
  hoistFunctionScope(ast, globalScope);
  hoistBlock(ast.body, globalScope, false);
  for (const s of ast.body) visit(s, globalScope, false);

  const serviceScope = scopeOfFunction.get(outerFn);
  const featureScope = scopeOfFunction.get(featureFn);
  for (const decl of decls) {
    if (decl.scope === serviceScope) decl.level = "service";
    else if (decl.scope === featureScope) decl.level = "feature";
  }
  for (const decl of serviceScope.vars.values()) {
    if (decl.kind === "function" && /^create[A-Z]/.test(decl.name)) factoryNames.add(decl.name);
  }

  // ── Roots and aliases ────────────────────────────────────────────────────
  // aliasOf: local decl -> { root: top-level decl, path: [segments] }
  const aliasOf = new Map();
  const tracked = (decl) => decl && (decl.level === "feature" || decl.level === "service");

  // A top-level `const x = createY(...)` whose createY is a services-scope
  // factory holds that service's interface.
  function isFactoryInstance(decl) {
    if (!tracked(decl) || decl.kind !== "const" || !decl.init) return false;
    const init = unwrap(decl.init);
    return init.type === "CallExpression" && init.callee.type === "Identifier"
      && factoryNames.has(init.callee.name) && references.get(init.callee)?.level === "service";
  }
  function isFactoryInstanceExpr(expr) {
    expr = unwrap(expr);
    return Boolean(expr && expr.type === "Identifier" && isFactoryInstance(references.get(expr)));
  }

  // The global object property a chain is rooted at (window.X..., self.X...).
  function globalRootOf(expr) {
    expr = unwrap(expr);
    let first = null;
    let depth = 0;
    for (;;) {
      if (!expr) return null;
      if (expr.type === "MemberExpression") {
        if (isGlobalObject(expr.object)) {
          const name = literalPropertyName(expr);
          first = name === null ? "[]" : name;
          return { property: first, depth };
        }
        depth += 1;
        expr = unwrap(expr.object);
        continue;
      }
      if (expr.type === "CallExpression") {
        const callee = unwrap(expr.callee);
        if (callee && callee.type === "MemberExpression" && VIEW_CALLS.has(literalPropertyName(callee))) {
          depth += 1;
          expr = unwrap(callee.object);
          continue;
        }
      }
      return null;
    }
  }

  // Resolve an expression to every { root, path, via } it may denote: a chain
  // rooted at a tracked binding, directly or through an alias. An alias may
  // hold several roots (flow-insensitive union over its assignments).
  function rootsOf(expr) {
    expr = unwrap(expr);
    const path = [];
    for (;;) {
      if (!expr) return [];
      if (expr.type === "MemberExpression") {
        const name = literalPropertyName(expr);
        path.unshift(name === null ? "[]" : name);
        expr = unwrap(expr.object);
        continue;
      }
      if (expr.type === "CallExpression") {
        const callee = unwrap(expr.callee);
        const method = callee && callee.type === "MemberExpression" ? literalPropertyName(callee) : null;
        if (method !== null && (VIEW_CALLS.has(method) || isFactoryInstanceExpr(callee.object))) {
          // A view call returns part of its receiver. A method of a service
          // interface returns state the service owns, so a later mutation
          // of that result bypasses the interface and is still a write.
          path.unshift(`${method}()`);
          expr = unwrap(callee.object);
          continue;
        }
        return [];
      }
      if (expr.type === "Identifier") {
        const decl = references.get(expr);
        if (!decl) return [];
        const found = [];
        if (tracked(decl)) found.push({ root: decl, path, via: null });
        for (const source of aliasOf.get(decl) || []) found.push({ root: source.root, path: [...source.path, ...path], via: decl });
        return found;
      }
      return [];
    }
  }

  function rootsOfValue(expr) {
    expr = unwrap(expr);
    if (!expr) return [];
    if (expr.type === "ConditionalExpression") return [...rootsOfValue(expr.consequent), ...rootsOfValue(expr.alternate)];
    if (expr.type === "LogicalExpression") return [...rootsOfValue(expr.left), ...rootsOfValue(expr.right)];
    if (expr.type === "AssignmentExpression" && expr.operator === "=") return rootsOfValue(expr.right);
    if (expr.type === "SequenceExpression") return rootsOfValue(expr.expressions.at(-1));
    return rootsOf(expr);
  }

  // Attribution only uses the root and the first path segment, so aliases
  // are keyed on those. That keeps the fixed point finite when a loop walks
  // a linked structure (n = n.next) and the path would otherwise grow.
  function bindAlias(target, source) {
    const decl = references.get(target);
    if (!decl || source.root === decl) return false;
    const key = `${source.root.start}:${source.path[0] ?? ""}`;
    let keys = aliasKeys.get(decl);
    if (!keys) { keys = new Set(); aliasKeys.set(decl, keys); aliasOf.set(decl, []); }
    if (keys.has(key)) return false;
    keys.add(key);
    aliasOf.get(decl).push({ root: source.root, path: source.path });
    return true;
  }

  function bindPatternAlias(pattern, source) {
    if (!pattern) return false;
    if (pattern.type === "Identifier") return bindAlias(pattern, source);
    if (pattern.type === "AssignmentPattern") return bindPatternAlias(pattern.left, source);
    if (pattern.type === "ObjectPattern") {
      let changed = false;
      for (const prop of pattern.properties) {
        if (prop.type === "RestElement") continue; // a rest copy is a new object
        const key = prop.computed ? (prop.key.type === "Literal" ? String(prop.key.value) : "[]") : prop.key.name ?? String(prop.key.value);
        changed = bindPatternAlias(prop.value, { root: source.root, path: [...source.path, key] }) || changed;
      }
      return changed;
    }
    if (pattern.type === "ArrayPattern") {
      let changed = false;
      for (const element of pattern.elements) {
        if (element && element.type !== "RestElement") {
          changed = bindPatternAlias(element, { root: source.root, path: [...source.path, "[]"] }) || changed;
        }
      }
      return changed;
    }
    return false;
  }

  function callbackElementParams(call) {
    const callee = unwrap(call.callee);
    if (!callee || callee.type !== "MemberExpression") return [];
    const method = literalPropertyName(callee);
    const index = ELEMENT_CALLBACKS.has(method) ? 0 : REDUCE_CALLBACKS.has(method) ? 1 : -1;
    if (index < 0) return [];
    const fn = call.arguments[0];
    if (!fn || !/FunctionExpression$/.test(fn.type)) return [];
    const param = fn.params[index];
    return param ? [{ param, receiver: callee.object }] : [];
  }

  // Fixed point: aliases can chain through other aliases.
  const aliasKeys = new Map();
  for (let changed = true; changed;) {
    changed = false;
    for (const event of events) {
      if (event.type === "declare") {
        for (const source of rootsOfValue(event.node.init)) changed = bindPatternAlias(event.node.id, source) || changed;
      } else if (event.type === "assign" && event.node.operator === "=") {
        const left = event.node.left;
        if (left.type !== "MemberExpression") {
          for (const source of rootsOfValue(event.node.right)) changed = bindPatternAlias(left, source) || changed;
        }
      } else if (event.type === "forHead" && event.node.type === "ForOfStatement") {
        const left = event.node.left.type === "VariableDeclaration" ? event.node.left.declarations[0].id : event.node.left;
        for (const source of rootsOf(event.node.right)) {
          changed = bindPatternAlias(left, { root: source.root, path: [...source.path, "[]"] }) || changed;
        }
      } else if (event.type === "call") {
        for (const { param, receiver } of callbackElementParams(event.node)) {
          for (const source of rootsOf(receiver)) {
            changed = bindPatternAlias(param, { root: source.root, path: [...source.path, "[]"] }) || changed;
          }
        }
      }
    }
  }

  // ── Writes ──────────────────────────────────────────────────────────────
  const writes = [];
  const globalWrites = [];
  function record(kind, rooted, node, detail) {
    writes.push({
      kind, detail, binding: rooted.root, path: rooted.path, alias: rooted.via ? rooted.via.name : null,
      module: moduleAt(node.start), line: lineAt(node.start), start: node.start,
    });
  }

  function isGlobalObject(expr) {
    expr = unwrap(expr);
    return expr && expr.type === "Identifier" && GLOBAL_OBJECTS.has(expr.name) && references.get(expr) === null;
  }

  function recordGlobal(kind, globalRoot, node) {
    // depth 0 publishes window.X itself; deeper writes mutate what X holds.
    globalWrites.push({
      kind: globalRoot.depth === 0 && kind !== "mutator" ? "publish" : kind,
      property: globalRoot.property, module: moduleAt(node.start), start: node.start,
    });
  }

  function targetWrite(target, kind, node, detail) {
    target = unwrap(target);
    if (!target) return;
    if (target.type === "Identifier") {
      const decl = references.get(target);
      if (tracked(decl)) record(kind === "update" ? "update" : "assign", { root: decl, path: [], via: null }, node, detail);
      return;
    }
    if (target.type === "MemberExpression") {
      const globalRoot = globalRootOf(target);
      if (globalRoot) { recordGlobal("property", globalRoot, node); return; }
      for (const rooted of rootsOf(target)) record("property", rooted, node, detail);
      return;
    }
    if (target.type === "ObjectPattern") {
      for (const prop of target.properties) targetWrite(prop.type === "RestElement" ? prop.argument : prop.value, kind, node, detail);
    } else if (target.type === "ArrayPattern") {
      for (const element of target.elements) targetWrite(element, kind, node, detail);
    } else if (target.type === "RestElement") targetWrite(target.argument, kind, node, detail);
    else if (target.type === "AssignmentPattern") targetWrite(target.left, kind, node, detail);
  }

  for (const event of events) {
    const node = event.node;
    if (event.type === "assign") targetWrite(node.left, "assign", node, node.operator);
    else if (event.type === "update") targetWrite(node.argument, "update", node, node.operator);
    else if (event.type === "delete") targetWrite(node.argument, "delete", node, "delete");
    else if (event.type === "forHead") {
      if (node.left.type !== "VariableDeclaration") targetWrite(node.left, "assign", node, node.type === "ForInStatement" ? "for-in" : "for-of");
    } else if (event.type === "call") {
      const callee = unwrap(node.callee);
      if (!callee || callee.type !== "MemberExpression") continue;
      const method = literalPropertyName(callee);
      const receiver = unwrap(callee.object);
      if (receiver && receiver.type === "Identifier" && references.get(receiver) === null
          && ((receiver.name === "Object" && OBJECT_TARGET_WRITERS.has(method))
            || (receiver.name === "Reflect" && REFLECT_TARGET_WRITERS.has(method)))) {
        const target = node.arguments[0];
        if (target && isGlobalObject(target)) {
          globalWrites.push({ kind: "mutator", property: `${receiver.name}.${method}`, module: moduleAt(node.start), start: node.start });
          continue;
        }
        const globalTarget = target && globalRootOf(target);
        if (globalTarget) { recordGlobal("mutator", { ...globalTarget, depth: globalTarget.depth + 1 }, node); continue; }
        for (const rooted of target ? rootsOf(target) : []) record("mutator", rooted, node, `${receiver.name}.${method}`);
        continue;
      }
      if (!MUTATORS.has(method)) continue;
      const globalReceiver = globalRootOf(receiver);
      if (globalReceiver) { recordGlobal("mutator", { ...globalReceiver, depth: globalReceiver.depth + 1 }, node); continue; }
      for (const rooted of rootsOf(receiver)) {
        if (rooted.path.length === 0 && isFactoryInstance(rooted.root)) continue;
        record("mutator", rooted, node, method);
      }
    }
  }
  // Every identifier with no lexical binding in this script: at runtime it
  // reads the global object, or throws a ReferenceError.
  const unresolved = [];
  for (const [node, decl] of references) {
    if (decl !== null) continue;
    unresolved.push({ name: node.name, module: moduleAt(node.start), line: lineAt(node.start), guarded: guarded.has(node) });
  }

  return { decls: decls.filter(tracked), writes, globalWrites, unresolved, strict: strictProgram };
}

// ── Pages ───────────────────────────────────────────────────────────────────

function inlineScripts(html) {
  return [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
}

function closureName(code, page, index) {
  if (page === "peer") return "peer";
  return code.includes("// owner-ui module: calls/") ? "calls" : index === 0 ? "owner" : `owner#${index}`;
}

function bindingMutability(decl) {
  if (decl.kind === "let" || decl.kind === "var") return "rebindable";
  if (decl.kind === "function" || decl.kind === "class") return "declaration";
  const init = decl.init && unwrap(decl.init);
  if (!init) return "rebindable";
  if (init.type === "Literal" || (init.type === "TemplateLiteral" && init.expressions.length === 0)
      || init.type === "ArrowFunctionExpression" || init.type === "FunctionExpression"
      || (init.type === "UnaryExpression" && init.argument.type === "Literal")) return "constant";
  return "object";
}

function censusPage(page, html) {
  const scripts = inlineScripts(html);
  if (!scripts.length) throw new CensusError(`${page}: no inline scripts`);
  const bindings = [];
  const writes = [];
  const globals = [];
  const unresolvedByClosure = [];
  scripts.forEach((code, index) => {
    const closure = closureName(code, page, index);
    const result = analyzeScript(code, { page, script: index });
    for (const decl of result.decls) {
      bindings.push({
        page, closure, level: decl.level, name: decl.name, kind: decl.kind,
        mutability: bindingMutability(decl), module: decl.module,
      });
    }
    for (const w of result.writes) {
      writes.push({
        page, closure, level: w.binding.level, binding: w.binding.name, declaredIn: w.binding.module,
        target: w.path.length ? `${w.binding.name}.${w.path[0]}` : w.binding.name,
        path: [w.binding.name, ...w.path].join("."),
        writer: w.module, line: w.line, kind: w.kind, detail: w.detail, alias: w.alias,
      });
    }
    for (const g of result.globalWrites) globals.push({ page, closure, property: g.property, writer: g.module, kind: g.kind });
    unresolvedByClosure.push({ closure, unresolved: result.unresolved });
  });
  // A closure that names another closure's top-level binding cannot reach
  // it: each closure is a private function scope. Unless the page publishes
  // that name on the global object, the reference throws a ReferenceError
  // at runtime. (`typeof name` probes are exempt; they never throw.)
  const published = new Set(globals.filter((g) => g.kind === "publish").map((g) => g.property));
  const crossClosure = [];
  for (const { closure, unresolved } of unresolvedByClosure) {
    for (const ref of unresolved) {
      if (ref.guarded || published.has(ref.name)) continue;
      const owner = bindings.find((b) => b.closure !== closure && b.name === ref.name);
      if (!owner) continue;
      crossClosure.push({
        page, closure, name: ref.name, module: ref.module, line: ref.line,
        declaredClosure: owner.closure, declaredIn: owner.module,
      });
    }
  }
  return { bindings, writes, globals, crossClosure };
}

// pages: { owner: "<path>" | { html }, peer: ... }
function runCensus(pages = DEFAULT_PAGES) {
  const all = { bindings: [], writes: [], globals: [], crossClosure: [] };
  for (const [page, source] of Object.entries(pages)) {
    const html = typeof source === "string" ? fs.readFileSync(source, "utf8") : source.html;
    const result = censusPage(page, html);
    all.bindings.push(...result.bindings);
    all.writes.push(...result.writes);
    all.globals.push(...result.globals);
    all.crossClosure.push(...result.crossClosure);
  }
  return all;
}

// Cross-module writes grouped into the baseline's entry key.
function crossModuleEntries(census) {
  const groups = new Map();
  for (const w of census.writes) {
    if (w.writer === w.declaredIn) continue;
    const key = [w.page, w.closure, w.target, w.declaredIn, w.writer].join("\u0000");
    let entry = groups.get(key);
    if (!entry) {
      entry = { page: w.page, closure: w.closure, target: w.target, declaredIn: w.declaredIn, writer: w.writer, writes: 0, kinds: {} };
      groups.set(key, entry);
    }
    entry.writes += 1;
    entry.kinds[w.kind] = (entry.kinds[w.kind] || 0) + 1;
  }
  return sortEntries([...groups.values()].map(sortKinds));
}

// Global (window/globalThis/self) properties are shared state with no lexical
// owner. The module that assigns window.X itself is its publisher. A write
// from any other module (assigning X again, or mutating what X holds) is a
// cross-module bridge write; so is every write to a property with several
// publishers. Properties no module publishes are platform objects
// (location, history, ...) and are reported separately, not baselined.
function globalBridgeEntries(census) {
  const byProperty = new Map();
  for (const g of census.globals) {
    const key = `${g.page}\u0000${g.property}`;
    if (!byProperty.has(key)) byProperty.set(key, []);
    byProperty.get(key).push(g);
  }
  const entries = [];
  for (const writes of byProperty.values()) {
    const publishers = [...new Set(writes.filter((g) => g.kind === "publish").map((g) => g.writer))].sort();
    if (!publishers.length) continue;
    const declaredIn = publishers.join(",");
    const groups = new Map();
    for (const g of writes) {
      if (publishers.length === 1 && g.writer === publishers[0]) continue;
      const key = `${g.closure}\u0000${g.writer}`;
      let entry = groups.get(key);
      if (!entry) {
        entry = { page: g.page, property: g.property, declaredIn, closure: g.closure, writer: g.writer, writes: 0, kinds: {} };
        groups.set(key, entry);
      }
      entry.writes += 1;
      entry.kinds[g.kind] = (entry.kinds[g.kind] || 0) + 1;
    }
    entries.push(...[...groups.values()].map(sortKinds));
  }
  return entries.sort((a, b) => cmp([a.page, a.property, a.closure, a.writer], [b.page, b.property, b.closure, b.writer]));
}

function platformGlobalWrites(census) {
  const published = new Set(census.globals.filter((g) => g.kind === "publish").map((g) => `${g.page}\u0000${g.property}`));
  return census.globals.filter((g) => !published.has(`${g.page}\u0000${g.property}`));
}

function cmp(a, b) {
  for (let i = 0; i < a.length; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

function sortEntries(entries) {
  return entries.sort((a, b) => cmp([a.page, a.closure, a.target, a.writer], [b.page, b.closure, b.target, b.writer]));
}

function sortKinds(entry) {
  const kinds = {};
  for (const kind of Object.keys(entry.kinds).sort()) kinds[kind] = entry.kinds[kind];
  return { ...entry, kinds };
}

function entryKey(e) {
  return [e.page, e.closure, e.target, e.declaredIn, e.writer].join(" | ");
}

function bridgeKey(e) {
  return [e.page, e.property, e.declaredIn, e.closure, e.writer].join(" | ");
}

function summarize(census) {
  const entries = crossModuleEntries(census);
  const total = entries.reduce((n, e) => n + e.writes, 0);
  const byTarget = new Map();
  for (const e of entries) byTarget.set(`${e.page}:${e.target}`, (byTarget.get(`${e.page}:${e.target}`) || 0) + e.writes);
  return { entries, total, byTarget };
}

// ── Baseline ────────────────────────────────────────────────────────────────

function loadBaseline(file = BASELINE_PATH) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    throw new CensusError(`cannot read baseline ${file}: ${error.message}`);
  }
}

// Compare the measured census to the baseline. Every difference is an error:
// a new or larger entry is new coupling; a smaller or vanished entry means
// the baseline overstates coupling and must be lowered in the same change.
function compareToBaseline(census, baseline) {
  const errors = [];
  if (!baseline || baseline.schema !== 1 || !Array.isArray(baseline.entries)) {
    return ["baseline must be { schema: 1, rationales: {...}, entries: [...] }"];
  }
  const rationales = baseline.rationales || {};
  const measured = new Map(crossModuleEntries(census).map((e) => [entryKey(e), e]));
  const recorded = new Map();
  for (const e of baseline.entries) {
    const key = entryKey(e);
    if (recorded.has(key)) errors.push(`duplicate baseline entry: ${key}`);
    recorded.set(key, e);
    if (typeof e.rationale !== "string" || !rationales[e.rationale]) {
      errors.push(`baseline entry has no justification: ${key}`);
    }
  }
  for (const [key, m] of measured) {
    const r = recorded.get(key);
    if (!r) errors.push(`new cross-module write (${m.writes}): ${key} ${JSON.stringify(m.kinds)}`);
    else if (r.writes !== m.writes || JSON.stringify(r.kinds) !== JSON.stringify(m.kinds)) {
      const direction = m.writes > r.writes ? "increased" : m.writes < r.writes ? "decreased; lower the baseline" : "changed kind";
      errors.push(`cross-module writes ${direction}: ${key} baseline=${r.writes} ${JSON.stringify(r.kinds)} measured=${m.writes} ${JSON.stringify(m.kinds)}`);
    }
  }
  for (const key of recorded.keys()) if (!measured.has(key)) errors.push(`baseline entry no longer measured; remove it: ${key}`);

  const bridges = new Map(globalBridgeEntries(census).map((e) => [bridgeKey(e), e]));
  const recordedBridges = new Map();
  for (const e of baseline.globalBridges || []) {
    const key = bridgeKey(e);
    if (recordedBridges.has(key)) errors.push(`duplicate global bridge entry: ${key}`);
    recordedBridges.set(key, e);
    if (typeof e.rationale !== "string" || !rationales[e.rationale]) errors.push(`global bridge has no justification: ${key}`);
  }
  for (const [key, m] of bridges) {
    const r = recordedBridges.get(key);
    if (!r) errors.push(`new multi-writer global bridge (${m.writes}): ${key}`);
    else if (r.writes !== m.writes || JSON.stringify(r.kinds) !== JSON.stringify(m.kinds)) {
      errors.push(`global bridge writes changed: ${key} baseline=${r.writes} ${JSON.stringify(r.kinds)} measured=${m.writes} ${JSON.stringify(m.kinds)}`);
    }
  }
  for (const key of recordedBridges.keys()) if (!bridges.has(key)) errors.push(`global bridge no longer measured; remove it: ${key}`);

  for (const id of Object.keys(rationales)) {
    const used = baseline.entries.some((e) => e.rationale === id) || (baseline.globalBridges || []).some((e) => e.rationale === id);
    if (!used) errors.push(`unused rationale: ${id}`);
    if (typeof rationales[id] !== "string" || rationales[id].trim().length < 40) errors.push(`rationale too thin to justify anything: ${id}`);
  }
  // A closure cannot reach another closure's top-level names. Every such
  // reference is a runtime ReferenceError (or, behind a typeof probe, dead
  // code) unless the page publishes the name; none is baselined.
  for (const ref of census.crossClosure || []) {
    errors.push(`cross-closure reference: ${ref.page} ${ref.closure} ${ref.module}:${ref.line} names ` +
      `${ref.name}, a top-level binding of the ${ref.declaredClosure} closure (${ref.declaredIn}); ` +
      "use that closure's published bridge");
  }
  for (const feature of baseline.migratedFeatures || []) {
    for (const target of feature.retiredTargets || []) {
      for (const w of census.writes) {
        if (w.page === feature.page && (w.target === target || w.path === target || w.path.startsWith(`${target}.`))) {
          errors.push(`retired ${feature.name} state is written again: ${w.path} in ${w.writer}`);
        }
      }
    }
    // Module-private state moved to its only writer: it must stay declared
    // there and no other module may write it.
    for (const owned of feature.moduleOwned || []) {
      const binding = census.bindings.find((b) => b.page === feature.page && b.name === owned.binding && b.module === owned.module);
      if (!binding) errors.push(`${feature.name} module-owned state ${owned.binding} is no longer declared in ${owned.module}`);
      for (const w of census.writes) {
        if (w.page === feature.page && w.binding === owned.binding && w.writer !== owned.module) {
          errors.push(`${feature.name} module-owned state ${owned.binding} (${owned.module}) is written from ${w.writer}`);
        }
      }
    }
    for (const owner of feature.owners || []) {
      const binding = census.bindings.find((b) => b.page === feature.page && b.closure === owner.closure && b.name === owner.binding);
      if (!binding) errors.push(`${feature.name} state owner is missing: ${owner.closure}:${owner.binding}`);
      for (const w of census.writes) {
        if (w.page === feature.page && w.closure === owner.closure && w.binding === owner.binding) {
          errors.push(`${feature.name} state owner ${owner.binding} is written directly: ${w.path} ${w.kind} in ${w.writer}`);
        }
      }
    }
  }
  return errors;
}

function writeBaseline(census, file = BASELINE_PATH) {
  const previous = fs.existsSync(file) ? loadBaseline(file) : { schema: 1, rationales: {}, entries: [] };
  const old = new Map((previous.entries || []).map((e) => [entryKey(e), e]));
  const oldBridges = new Map((previous.globalBridges || []).map((e) => [bridgeKey(e), e]));
  const entries = crossModuleEntries(census).map((e) => ({ ...e, rationale: old.get(entryKey(e))?.rationale ?? "UNJUSTIFIED" }));
  const globalBridges = globalBridgeEntries(census).map((e) => ({ ...e, rationale: oldBridges.get(bridgeKey(e))?.rationale ?? "UNJUSTIFIED" }));
  const next = { ...previous, schema: 1, entries, globalBridges };
  fs.writeFileSync(file, JSON.stringify(next, null, 2) + "\n", "utf8");
  return next;
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function main(argv) {
  const args = new Set(argv);
  const census = runCensus();
  if (args.has("--json")) {
    process.stdout.write(JSON.stringify({
      bindings: census.bindings, crossModule: crossModuleEntries(census), globalBridges: globalBridgeEntries(census),
      crossClosure: census.crossClosure, platformGlobalWrites: platformGlobalWrites(census),
    }, null, 2) + "\n");
    return 0;
  }
  if (args.has("--write-baseline")) {
    const next = writeBaseline(census);
    const missing = [...next.entries, ...next.globalBridges].filter((e) => e.rationale === "UNJUSTIFIED").length;
    console.log(`baseline written: ${next.entries.length} entries, ${next.globalBridges.length} global bridges, ${missing} need a rationale`);
    return 0;
  }
  const { entries, total, byTarget } = summarize(census);
  const bridges = globalBridgeEntries(census);
  console.log(`ownership census: ${census.bindings.length} top-level bindings, ${census.writes.length} writes, ` +
    `${total} cross-module writes in ${entries.length} (target, writer) entries, ${bridges.length} cross-module global bridge entries, ` +
    `${(census.crossClosure || []).length} cross-closure references`);
  if (args.has("--targets")) {
    for (const [target, n] of [...byTarget].sort((a, b) => b[1] - a[1] || cmp([a[0]], [b[0]]))) console.log(`  ${String(n).padStart(5)}  ${target}`);
  }
  if (args.has("--check")) {
    const errors = compareToBaseline(census, loadBaseline());
    if (errors.length) {
      for (const e of errors) console.error(`  ${e}`);
      console.error(`ownership census differs from ${path.relative(ROOT, BASELINE_PATH)}: ${errors.length} problem(s)`);
      return 1;
    }
    console.log("ownership census matches the justified baseline");
  }
  return 0;
}

module.exports = {
  CensusError, analyzeScript, censusPage, runCensus, crossModuleEntries, globalBridgeEntries, platformGlobalWrites,
  compareToBaseline, loadBaseline, writeBaseline, summarize, entryKey, bridgeKey, BASELINE_PATH, DEFAULT_PAGES, MUTATORS, VIEW_CALLS,
};

if (require.main === module) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof CensusError ? error.message : error.stack);
    process.exitCode = 2;
  }
}
