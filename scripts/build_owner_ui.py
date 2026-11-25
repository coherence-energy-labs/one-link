#!/usr/bin/env python3
"""Build the offline owner UI from its canonical feature/service sources.

No npm install, network access, minification, or runtime module loader is
required. Ordered feature modules retain the two established browser closure
lifecycles. Isolated services declare dependencies in factory parameters.
Run ``python scripts/build_owner_ui.py --check`` in CI to reject stale output.
"""

from __future__ import annotations

import argparse
import difflib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "frontend" / "owner"
OUTPUT = ROOT / "src" / "one_link" / "web" / "index.html"
FINGERPRINT = "__ONE_LINK_SOURCE_FINGERPRINT__"
GROUP_WRAPPERS = {
    "owner": ("(() => {\n", "})();\n"),
    "calls": ("(function () {\n", "})();\n"),
}
CALL_HEADER = (
    "// Living Presence Tier α-pre - call UI driver.\n"
    "// All call actions go through POST /api/v1/calls; state updates\n"
    '// arrive over the WebSocket as "call_event" tail events.\n'
)


class BuildError(ValueError):
    """The canonical source set cannot produce a valid owner UI artifact."""


def _read(source: Path, relative: str) -> str:
    if not isinstance(relative, str) or not relative:
        raise BuildError("module/template paths must be nonempty strings")
    path = source / relative
    if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
        raise BuildError(f"source path must stay within owner_ui: {relative}")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise BuildError(f"cannot read {relative}: {exc}") from exc
    if not text.endswith("\n"):
        raise BuildError(f"source must end with a newline: {relative}")
    return text


def load_manifest(source: Path = SOURCE) -> dict:
    try:
        manifest = json.loads(_read(source, "manifest.json"))
    except json.JSONDecodeError as exc:
        raise BuildError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise BuildError("unsupported owner UI manifest schema")
    groups = manifest.get("groups")
    if (
        not isinstance(groups, list)
        or not all(isinstance(group, dict) for group in groups)
        or [group.get("name") for group in groups] != list(GROUP_WRAPPERS)
    ):
        raise BuildError("manifest must contain owner and calls groups in that order")
    seen: set[str] = set()
    factories: set[str] = set()
    for group in groups:
        modules = group.get("modules")
        if not isinstance(modules, list) or not modules:
            raise BuildError(f"empty module group: {group['name']}")
        for module in modules:
            if not isinstance(module, dict):
                raise BuildError("module entries must be objects")
            path = module.get("path")
            if not isinstance(path, str) or not re.fullmatch(r"(?:main|calls|services)/[a-z_]+\.js", path):
                raise BuildError(f"invalid module path: {path!r}")
            if path in seen:
                raise BuildError(f"duplicate module: {path}")
            seen.add(path)
            if not module.get("responsibility"):
                raise BuildError(f"module has no ownership description: {path}")
            kind = module.get("kind")
            if kind not in {"feature", "service"}:
                raise BuildError(f"invalid module kind: {path}")
            expected_area = "services" if kind == "service" else "main" if group["name"] == "owner" else "calls"
            if path.split("/", 1)[0] != expected_area:
                raise BuildError(f"module is outside its declared lifecycle: {path}")
            if kind == "service":
                factory = module.get("factory")
                if not isinstance(factory, str) or not re.fullmatch(r"create[A-Z][A-Za-z]+", factory):
                    raise BuildError(f"service has no valid factory interface: {path}")
                if factory in factories:
                    raise BuildError(f"duplicate service factory: {factory}")
                factories.add(factory)
                if not re.search(rf"^function {factory}\(", _read(source, path), re.M):
                    raise BuildError(f"service does not declare {factory}: {path}")
    available = {p.relative_to(source).as_posix() for p in source.rglob("*.js")}
    if available != seen:
        raise BuildError(
            "module inventory mismatch; "
            f"unregistered={sorted(available - seen)}, missing={sorted(seen - available)}"
        )
    return manifest


def script_sources(source: Path = SOURCE, manifest: dict | None = None) -> dict[str, str]:
    manifest = manifest or load_manifest(source)
    scripts: dict[str, str] = {}
    for group in manifest["groups"]:
        name = group["name"]
        opening, closing = GROUP_WRAPPERS[name]
        # Service definitions live OUTSIDE the feature closure. They cannot
        # accidentally capture its state/api/media variables: collaborators
        # must cross each factory's explicit parameter boundary. This outer
        # scope still keeps the factory names out of the browser global scope.
        parts = [CALL_HEADER if name == "calls" else "", "(() => {\n"]
        for kind in ("service", "feature"):
            if kind == "feature":
                parts.append(opening)
            for module in group["modules"]:
                if module["kind"] != kind:
                    continue
                path = module["path"]
                body = _read(source, path)
                if re.search(r"</script\b", body, re.I):
                    raise BuildError(f"inline script terminator in module: {path}")
                parts.extend((f"// owner-ui module: {path}\n", body))
        parts.extend((closing, "})();\n"))
        scripts[name] = "".join(parts)
    return scripts


def build(source: Path = SOURCE) -> str:
    manifest = load_manifest(source)
    html = _read(source, manifest.get("template"))
    for name, script in script_sources(source, manifest).items():
        marker = f"<!-- owner-ui:script {name} -->"
        if html.count(marker) != 1:
            raise BuildError(f"template must contain exactly one {marker}")
        html = html.replace(marker, f"<script>\n{script}</script>")
    if "<!-- owner-ui:script " in html:
        raise BuildError("template has an unresolved script marker")
    fingerprint_declaration = f'const PAGE_SOURCE_FINGERPRINT = "{FINGERPRINT}";'
    if html.count(fingerprint_declaration) != 1:
        raise BuildError("generated HTML must preserve the source fingerprint declaration")
    return html


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if committed HTML differs; do not write")
    parser.add_argument("--source", type=Path, default=SOURCE, help="canonical owner_ui source directory")
    parser.add_argument("--output", type=Path, default=OUTPUT, help="generated HTML artifact")
    args = parser.parse_args(argv)
    try:
        expected = build(args.source)
        existing = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
    except (BuildError, OSError, UnicodeError) as exc:
        print(f"Owner UI build failed: {exc}", file=sys.stderr)
        return 2
    if expected == existing:
        print("Owner UI generated HTML is current.")
        return 0
    if args.check:
        print("Owner UI generated HTML is stale. Run: python scripts/build_owner_ui.py", file=sys.stderr)
        diff = difflib.unified_diff(
            existing.splitlines(), expected.splitlines(),
            fromfile=str(args.output), tofile="canonical owner_ui build", lineterm="",
        )
        for index, line in enumerate(diff):
            if index >= 100:
                print("... diff truncated; rebuild to inspect the complete change", file=sys.stderr)
                break
            print(line, file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(expected, encoding="utf-8", newline="\n")
    print(f"Built owner UI: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
