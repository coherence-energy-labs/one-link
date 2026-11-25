"""Audit the registry ancestors of verified local Cargo backports against OSV.

Cargo's path resolution must not remove a package from ongoing advisory checks.
Every backport selected anywhere in the repository (every workspace manifest;
see verify_vendor_patches.inspect_repository) is queried as its original
registry version. This gate retains the complete upstream replies and accepts
only exact advisory IDs covered by a source backport whose crate archive and
diff were verified in this invocation. A backport declares the IDs it covers;
an empty list declares that it covers none, so every finding fails. New
findings, incomplete replies and query failures fail closed.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException, IncompleteRead
import json
from pathlib import Path
import re
import sys
import tarfile
from typing import Any
import urllib.error
import urllib.request

if __package__:
    from .verify_vendor_patches import ROOT, VendorError, inspect_repository
else:
    from verify_vendor_patches import ROOT, VendorError, inspect_repository


OSV_URL = "https://api.osv.dev/v1/query"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 20


def query_osv(payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        OSV_URL, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "one-link-vendor-audit/1"},
    )
    try:
        # OSV_URL is the fixed HTTPS endpoint, not a supplied URL or scheme.
        response = urllib.request.urlopen(request, timeout=45)  # nosec B310
    except urllib.error.HTTPError as exc:
        response = exc  # Preserve the response body for failed HTTP requests too.
    with response:
        incomplete = False
        try:
            body = response.read(MAX_RESPONSE_BYTES + 1)
        except IncompleteRead as exc:
            body = exc.partial
            incomplete = True
        valid_utf8 = True
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            text = body.decode("utf-8", errors="replace")
            valid_utf8 = False
        return {
            "http_status": response.status,
            "body": text,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "response_too_large": len(body) > MAX_RESPONSE_BYTES,
            "response_incomplete": incomplete,
            "response_valid_utf8": valid_utf8,
        }


def _remedy(backport: dict[str, Any]) -> dict[str, str]:
    """The upstream fix a backport reproduces: a commit, or a hashed registry release."""
    remedy: dict[str, str] = {}
    commit = backport.get("upstream_fix_commit")
    if commit is not None:
        if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            raise VendorError("upstream_fix_commit must be an exact 40-character commit SHA")
        remedy["upstream_fix_commit"] = commit
    url, digest = backport.get("reference_crate_url"), backport.get("reference_crate_sha256")
    if url is not None or digest is not None:
        if (not isinstance(url, str) or re.fullmatch(r"https://static\.crates\.io/crates/[^/]+/[^/]+\.crate", url) is None
                or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
            raise VendorError("a reference release needs a canonical crates.io URL and its SHA-256")
        remedy.update(reference_crate_url=url, reference_crate_sha256=digest)
    if not remedy:
        raise VendorError("backport must name its upstream remedy (upstream_fix_commit or reference_crate_url)")
    return remedy


def audit(root: Path) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "one-link-vendor-advisory-audit/v2",
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "status": "failed", "endpoint": OSV_URL, "packages": [], "errors": [],
        "scope": ("Registry ancestors of every exact verified local backport in the repository; "
                  "no original version is relabeled."),
    }
    try:
        inspected = inspect_repository(root, fetch_upstream=True)["packages"]
        if not inspected:
            raise VendorError("no reviewed local packages were selected for advisory qualification")
        if not all(value["upstream_archive_verified"] for value in inspected.values()):
            raise VendorError("advisory disposition requires verified original crate archives and diffs")
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, HTTPException) as exc:
        report["errors"].append(f"source provenance verification failed: {exc}")
        return report

    for (name, version), value in sorted(inspected.items()):
        entry: dict[str, Any] = {
            "package": {"ecosystem": "crates.io", "name": name, "version": version},
            "manifests": value.get("manifests", []),
            "responses": [], "advisories": [], "status": "failed",
        }
        report["packages"].append(entry)
        try:
            proof = value["proof"]
            backport = proof["backport"]
            if "advisories" not in backport:
                raise VendorError("backport must declare the exact advisory IDs it covers "
                                  "(an empty list declares that it covers none)")
            accepted = backport["advisories"]
            if not isinstance(accepted, list) or not all(
                isinstance(identifier, str) and identifier for identifier in accepted
            ) or len(set(accepted)) != len(accepted):
                raise VendorError("backport must declare exact, distinct advisory IDs")
            entry.update({
                "source_tree_sha256": proof["source_tree_sha256"],
                "upstream_crate_sha256": proof["upstream"]["crate_sha256"],
                "patch_sha256": backport["patch_sha256"],
                **_remedy(backport),
                "source_provenance_verified": True,
                "reviewed_backport_advisories": accepted,
            })
            payload = {"package": {"ecosystem": "crates.io", "name": name}, "version": version}
            seen_tokens = set()
            for _ in range(MAX_PAGES):
                response = query_osv(payload)
                entry["responses"].append({"request": dict(payload), **response})
                if (response["http_status"] != 200 or response["response_too_large"]
                        or response["response_incomplete"] or not response["response_valid_utf8"]):
                    raise VendorError("OSV query failed or returned an invalid/incomplete response")
                document = json.loads(response["body"])
                if not isinstance(document, dict) or not set(document) <= {"vulns", "next_page_token"}:
                    raise VendorError("OSV query returned an invalid response")
                findings = document.get("vulns", [])
                if not isinstance(findings, list):
                    raise VendorError("OSV findings must be a list")
                for finding in findings:
                    if not isinstance(finding, dict) or not isinstance(finding.get("id"), str):
                        raise VendorError("OSV returned a finding without an advisory ID")
                    identifier = finding["id"]
                    covered = identifier in accepted
                    # Alias matches alone cannot authorize an unfamiliar ID.
                    # Every returned finding remains verbatim in the raw reply.
                    entry["advisories"].append({
                        "id": identifier, "aliases": finding.get("aliases", []),
                        "disposition": "covered-by-verified-source-backport" if covered else "unreviewed-affected-advisory",
                    })
                    if not covered:
                        report["errors"].append(f"{name} {version}: unreviewed affected advisory {identifier}")
                token = document.get("next_page_token", "")
                if not isinstance(token, str):
                    raise VendorError("OSV returned an invalid pagination token")
                if not token:
                    break
                if token in seen_tokens:
                    raise VendorError("OSV returned an invalid or repeated pagination token")
                seen_tokens.add(token)
                payload = {**payload, "page_token": token}
            else:
                raise VendorError("OSV result exceeded the bounded pagination limit")
            if all(item["disposition"] == "covered-by-verified-source-backport"
                   for item in entry["advisories"]):
                entry["status"] = "passed"
        except (OSError, ValueError, KeyError, TypeError, HTTPException) as exc:
            entry["error"] = str(exc)
            report["errors"].append(f"{name} {version}: {exc}")
    if not report["errors"] and all(entry["status"] == "passed" for entry in report["packages"]):
        report["status"] = "passed"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository whose backports are audited")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    report = audit(args.root)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for entry in report["packages"]:
        for finding in entry["advisories"]:
            print(f"UPSTREAM ADVISORY {entry['package']['name']} {finding['id']}: {finding['disposition']}")
    print(json.dumps({"status": report["status"], "errors": report["errors"],
                      "report": str(args.report)}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
