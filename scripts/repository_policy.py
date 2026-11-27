"""Prepare and verify repository ruleset changes without contacting GitHub.

The proposal preserves the observed ruleset's existing conditions, bypass
actors and rules, then strengthens PR review and required-check requirements.
Only a separately authorized administrator applies it. A proposal is not
evidence that GitHub enforces the policy; verify a fresh API readback afterward.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github/repository-policy.json"
WRITABLE_FIELDS = ("name", "target", "enforcement", "conditions", "bypass_actors", "rules")


def proposal(observed: dict, policy: dict) -> dict:
    if observed.get("target") != "branch" or observed.get("name") != policy["ruleset_name"]:
        raise ValueError("refusing to alter a different ruleset")
    if "bypass_actors" not in observed or "conditions" not in observed:
        raise ValueError("a complete authenticated ruleset read is required")
    result = {key: copy.deepcopy(observed[key]) for key in WRITABLE_FIELDS if key in observed}
    result["enforcement"] = "active"
    rules = result.setdefault("rules", [])
    if len({rule["type"] for rule in rules}) != len(rules):
        raise ValueError("duplicate rule types require manual review")
    indexed = {rule["type"]: rule for rule in rules}
    for name in ("deletion", "non_fast_forward"):
        if name not in indexed:
            rule = {"type": name}
            rules.append(rule)
            indexed[name] = rule
    review = indexed.get("pull_request")
    if review is None:
        review = {"type": "pull_request", "parameters": {}}
        rules.append(review)
    params = review.setdefault("parameters", {})
    params["required_approving_review_count"] = max(
        params.get("required_approving_review_count", 0), policy["minimum_approvals"])
    params["dismiss_stale_reviews_on_push"] = True
    params["required_review_thread_resolution"] = True
    checks = indexed.get("required_status_checks")
    if checks is None:
        checks = {"type": "required_status_checks", "parameters": {}}
        rules.append(checks)
    params = checks.setdefault("parameters", {})
    params["strict_required_status_checks_policy"] = True
    required = params.setdefault("required_status_checks", [])
    by_context = {check["context"]: check for check in required}
    for check in policy["required_status_checks"]:
        if check["context"] in by_context:
            current = by_context[check["context"]]
            if current.get("integration_id") not in (None, check["integration_id"]):
                raise ValueError(f"conflicting check producer for {check['context']}")
            current["integration_id"] = check["integration_id"]
        else:
            required.append(copy.deepcopy(check))
    return result


def validate(observed: dict, policy: dict) -> list[str]:
    errors: list[str] = []
    if observed.get("name") != policy["ruleset_name"] or observed.get("target") != "branch":
        errors.append("wrong branch ruleset")
    if observed.get("enforcement") != "active":
        errors.append("ruleset is not active")
    scope = observed.get("conditions", {}).get("ref_name", {})
    if "~DEFAULT_BRANCH" not in scope.get("include", []) or scope.get("exclude"):
        errors.append("default branch scope is missing or has unreviewed exclusions")
    # The reviewed baseline has no bypass actors. Do not silently authorize
    # bypass while reporting that the baseline policy is enforced.
    if observed.get("bypass_actors") != policy["bypass_actors"]:
        errors.append("bypass actors differ from the reviewed baseline")
    rules = {rule["type"]: rule for rule in observed.get("rules", [])}
    for name in ("deletion", "non_fast_forward"):
        if name not in rules:
            errors.append(f"missing {name} restriction")
    review = rules.get("pull_request", {}).get("parameters", {})
    if review.get("required_approving_review_count", 0) < policy["minimum_approvals"]:
        errors.append("insufficient required approvals")
    for option in ("dismiss_stale_reviews_on_push", "required_review_thread_resolution"):
        if review.get(option) is not True:
            errors.append(f"missing {option}")
    checks = rules.get("required_status_checks", {}).get("parameters", {})
    if checks.get("strict_required_status_checks_policy") is not True:
        errors.append("required checks do not require an up-to-date branch")
    actual = {(c["context"], c.get("integration_id"))
              for c in checks.get("required_status_checks", [])}
    for check in policy["required_status_checks"]:
        if (check["context"], check["integration_id"]) not in actual:
            errors.append(f"missing required check/producer: {check['context']}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observed", type=Path, required=True,
                        help="JSON from a current GET /repos/{owner}/{repo}/rulesets/{id}")
    parser.add_argument("--policy", type=Path, default=POLICY)
    parser.add_argument("--proposal", type=Path, help="write a complete PUT body; never applies it")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    report: dict = {"schema": "one-link-repository-policy/v1", "status": "failed"}
    try:
        observed = json.loads(args.observed.read_text(encoding="utf-8-sig"))
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        if args.proposal:
            drafted = proposal(observed, policy)
            args.proposal.parent.mkdir(parents=True, exist_ok=True)
            args.proposal.write_text(json.dumps(drafted, indent=2) + "\n", encoding="utf-8")
            report.update(status="proposal", proposal_errors=validate(drafted, policy))
        report["observed_errors"] = validate(observed, policy)
        report["observed_policy_passed"] = not report["observed_errors"]
        if not args.proposal:
            report["status"] = "passed" if report["observed_policy_passed"] else "failed"
    except (OSError, ValueError, KeyError, TypeError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" or (
        report["status"] == "proposal" and not report.get("proposal_errors")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
