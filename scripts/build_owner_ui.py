#!/usr/bin/env python3
"""Build offline owner and peer pages from canonical feature/service sources.

No npm install, network access, minification, or runtime module loader is
required. Ordered feature modules retain the established browser closure
lifecycles. Isolated services declare dependencies in factory parameters.
The historical entry point checks both pages by default. Use ``--page owner``
or ``--page peer`` for a single artifact. CI can keep running
``python scripts/build_owner_ui.py --check`` to reject either stale output.
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
PEER_SOURCE = ROOT / "frontend" / "peer"
PEER_OUTPUT = ROOT / "src" / "one_link" / "web" / "peer.html"
PAGE_SOURCES = {"owner": SOURCE, "peer": PEER_SOURCE}
PAGE_OUTPUTS = {"owner": OUTPUT, "peer": PEER_OUTPUT}
PAGE_GROUPS = {"owner": ["owner", "calls"], "peer": ["peer"]}
FEATURE_AREAS = {
    "owner": {"owner": {"main"}, "calls": {"calls"}},
    "peer": {"peer": {"identity", "rendezvous", "transport", "pairing", "messages", "daemon_chat", "ui"}},
}
FINGERPRINT = "__ONE_LINK_SOURCE_FINGERPRINT__"
GROUP_WRAPPERS = {
    "owner": ("(() => {\n", "})();\n"),
    "calls": ("(function () {\n", "})();\n"),
    "peer": ("(() => {\n", "})();\n"),
}
CALL_HEADER = (
    "// Living Presence Tier α-pre - call UI driver.\n"
    "// All call actions go through POST /api/v1/calls; state updates\n"
    '// arrive over the WebSocket as "call_event" tail events.\n'
)


class BuildError(ValueError):
    """The canonical source set cannot produce a valid browser artifact."""


def _read(source: Path, relative: str) -> str:
    if not isinstance(relative, str) or not relative:
        raise BuildError("module/template paths must be nonempty strings")
    path = source / relative
    if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
        raise BuildError(f"source path must stay within the canonical directory: {relative}")
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
        raise BuildError("unsupported browser source manifest schema")
    page = manifest.get("page", "owner")
    if not isinstance(page, str) or page not in PAGE_GROUPS:
        raise BuildError(f"unsupported browser page: {page!r}")
    groups = manifest.get("groups")
    if (
        not isinstance(groups, list)
        or not all(isinstance(group, dict) for group in groups)
        or [group.get("name") for group in groups] != PAGE_GROUPS[page]
    ):
        raise BuildError(f"manifest must contain {PAGE_GROUPS[page]} groups in that order")
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
            if not isinstance(path, str) or not re.fullmatch(r"[a-z_]+/[a-z0-9_]+\.js", path):
                raise BuildError(f"invalid module path: {path!r}")
            if path in seen:
                raise BuildError(f"duplicate module: {path}")
            seen.add(path)
            if not module.get("responsibility"):
                raise BuildError(f"module has no ownership description: {path}")
            kind = module.get("kind")
            if kind not in {"feature", "service"}:
                raise BuildError(f"invalid module kind: {path}")
            allowed_areas = {"services"} if kind == "service" else FEATURE_AREAS[page][group["name"]]
            if path.split("/", 1)[0] not in allowed_areas:
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
    page = manifest.get("page", "owner")
    scripts: dict[str, str] = {}
    for group in manifest["groups"]:
        name = group["name"]
        opening, closing = GROUP_WRAPPERS[name]
        # Service definitions live OUTSIDE the feature closure. They cannot
        # accidentally capture its state/api/media variables: collaborators
        # must cross each factory's explicit parameter boundary. This outer
        # scope still keeps the factory names out of the browser global scope.
        parts = [CALL_HEADER if name == "calls" else "", "(() => {\n"]
        if page == "peer":
            # The original peer closure is strict. Its extracted services must
            # retain those semantics as well as the inner feature lifecycle.
            parts.append('  "use strict";\n')
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
                parts.extend((f"// {page}-ui module: {path}\n", body))
        parts.extend((closing, "})();\n"))
        scripts[name] = "".join(parts)
    return scripts


def build(source: Path = SOURCE) -> str:
    manifest = load_manifest(source)
    page = manifest.get("page", "owner")
    html = _read(source, manifest.get("template"))
    for name, script in script_sources(source, manifest).items():
        marker = f"<!-- {page}-ui:script {name} -->"
        if html.count(marker) != 1:
            raise BuildError(f"template must contain exactly one {marker}")
        html = html.replace(marker, f"<script>\n{script}</script>")
    if re.search(r"<!-- [a-z]+-ui:script ", html):
        raise BuildError("template has an unresolved script marker")
    fingerprint_declaration = f'const PAGE_SOURCE_FINGERPRINT = "{FINGERPRINT}";'
    if page == "owner" and html.count(fingerprint_declaration) != 1:
        raise BuildError("generated HTML must preserve the source fingerprint declaration")
    return html


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if committed HTML differs; do not write")
    parser.add_argument("--page", choices=["owner", "peer", "all"], help="page to build (default: both)")
    parser.add_argument("--source", type=Path, help="custom canonical source directory for one page")
    parser.add_argument("--output", type=Path, help="custom generated artifact for one page")
    args = parser.parse_args(argv)
    try:
        if args.source is not None or args.output is not None:
            if args.page == "all":
                raise BuildError("custom source/output requires a single page")
            source = args.source or PAGE_SOURCES[args.page or "owner"]
            page = load_manifest(source).get("page", "owner")
            if args.page is not None and page != args.page:
                raise BuildError("custom source manifest differs from --page")
            targets = [(page, source, args.output or PAGE_OUTPUTS[page])]
        else:
            pages = PAGE_SOURCES if args.page in {None, "all"} else [args.page]
            targets = [(page, PAGE_SOURCES[page], PAGE_OUTPUTS[page]) for page in pages]
        result = 0
        for page, source, output in targets:
            result = max(result, _build_target(page, source, output, check=args.check))
        return result
    except (BuildError, OSError, UnicodeError) as exc:
        print(f"Browser UI build failed: {exc}", file=sys.stderr)
        return 2


def _build_target(page: str, source: Path, output: Path, *, check: bool) -> int:
    expected = build(source)
    existing = output.read_text(encoding="utf-8") if output.exists() else ""
    if expected == existing:
        print(f"{page.title()} UI generated HTML is current.")
        return 0
    if check:
        print(f"{page.title()} UI generated HTML is stale. Run: python scripts/build_owner_ui.py", file=sys.stderr)
        diff = difflib.unified_diff(
            existing.splitlines(), expected.splitlines(),
            fromfile=str(output), tofile=f"canonical {page}_ui build", lineterm="",
        )
        for index, line in enumerate(diff):
            if index >= 100:
                print("... diff truncated; rebuild to inspect the complete change", file=sys.stderr)
                break
            print(line, file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(expected, encoding="utf-8", newline="\n")
    print(f"Built {page} UI: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
