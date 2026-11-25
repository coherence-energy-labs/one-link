"""Contract tests for the dudect timing-leak driver (scripts/run_ct_timing.py).

They run everywhere without building anything. They pin:

* the statistics the driver recomputes independently of the binary: Welch's
  t on hand-derived samples, the defining property of the minimum detectable
  effect, and the shift sensitivity of a cropped mean;
* the verdict logic, including the ways a run must NOT pass: a leak, a low
  power run, a negative control that is not detected (blind), a null control
  that is flagged (biased), and a binary result whose numbers disagree with
  the recomputation;
* the target table in native/ol_ct_audit/src/timing.rs against the Valgrind
  audit cases in main.rs.
"""

from __future__ import annotations

import json
import math
import random
import re
from pathlib import Path

import pytest

from scripts import run_ct_timing as timing

ROOT = Path(__file__).resolve().parents[1]
AUDIT_SRC = ROOT / "native" / "ol_ct_audit" / "src"


def dudect_percentiles() -> list[float]:
    return [1 - 0.5 ** (10 * (i + 1) / 100) for i in range(100)]


def moments(values: list[float]) -> tuple[int, float, float]:
    n = len(values)
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / (n - 1) if n > 1 else 0.0
    return n, mean, var


def synth(fixed: list[int], rand: list[int]) -> dict:
    """A result shaped like `ol_ct_audit --dudect`, from two integer samples."""
    pooled = sorted(fixed + rand)
    thresholds = [pooled[min(int(len(pooled) * p), len(pooled) - 1)] for p in dudect_percentiles()]

    def bins(sample: list[int]) -> list[int]:
        counts = [0] * (len(thresholds) + 1)
        for x in sample:
            counts[sum(1 for t in thresholds if t <= x)] += 1
        return counts

    crops = {k: [] for k in ("percentile", "threshold", "n_fixed", "n_random", "mean_fixed", "mean_random",
                             "var_fixed", "var_random", "t", "mde", "sensitivity", "mde_shift")}
    hist = {"min": pooled[0], "max": pooled[-1], "fixed": bins(fixed), "random": bins(rand)}
    pooled_counts = [a + b for a, b in zip(hist["fixed"], hist["random"])]
    for row in range(len(thresholds) + 1):
        keep = (lambda x: True) if row == 0 else (lambda x, c=thresholds[row - 1]: x < c)
        a = [float(x) for x in fixed if keep(x)]
        b = [float(x) for x in rand if keep(x)]
        n0, m0, v0 = moments(a) if a else (0, 0.0, 0.0)
        n1, m1, v1 = moments(b) if b else (0, 0.0, 0.0)
        t, se = timing.welch(n0, m0, v0, n1, m1, v1)
        mde = None if se is None else timing.T_THRESHOLD * se
        s = 1.0 if row == 0 else timing.shift_sensitivity(
            thresholds, pooled_counts, hist["min"], hist["max"], row - 1, n0 + n1, timing.pooled_mean(n0, m0, n1, m1)
        )
        eff = timing.effective_sensitivity(s)
        values = {
            "percentile": None if row == 0 else dudect_percentiles()[row - 1],
            "threshold": None if row == 0 else thresholds[row - 1],
            "n_fixed": n0, "n_random": n1, "mean_fixed": m0, "mean_random": m1, "var_fixed": v0,
            "var_random": v1, "t": t, "mde": mde, "sensitivity": s,
            "mde_shift": None if mde is None or eff <= 0 else mde / eff,
        }
        for key, value in values.items():
            crops[key].append(value)
    return {
        "crops": crops,
        "histogram": hist,
        "measurements": {"fixed": len(fixed), "random": len(rand)},
        "net_median": pooled[len(pooled) // 2],
        "reading_quantum": 1,
        "headline": None,
        "verdict": None,
    }


def settle(result: dict, bound: float = 0.01) -> timing.Recomputed:
    """Fill in the headline and verdict as a consistent binary would."""
    rec = timing.recompute(result, bound)
    if rec.headline_row is not None:
        result["headline"] = {"row": rec.headline_row, "mde80": rec.mde80}
    result["verdict"] = rec.verdict
    return timing.recompute(result, bound)


def gaussian(rng: random.Random, n: int, mean: float, sd: float) -> list[int]:
    return [round(rng.gauss(mean, sd)) for _ in range(n)]


def test_welch_matches_hand_derived_values():
    # a = 1..5 (mean 3, var 2.5), b = 2,4,..,10 (mean 6, var 10).
    t, se = timing.welch(5, 3.0, 2.5, 5, 6.0, 10.0)
    assert t == pytest.approx(3 / math.sqrt(2.5), rel=1e-12)
    assert se == pytest.approx(math.sqrt(2.5), rel=1e-12)
    # Unequal sizes: (n 3, mean 2, var 1) against (n 5, mean 8, var 10).
    t, _ = timing.welch(3, 2.0, 1.0, 5, 8.0, 10.0)
    assert t == pytest.approx(6 / math.sqrt(1 / 3 + 2), rel=1e-12)
    assert timing.welch(1, 0.0, 0.0, 5, 8.0, 10.0) == (None, None)
    assert timing.welch(4, 2.0, 0.0, 4, 2.0, 0.0)[0] is None


def test_a_shift_of_exactly_the_mde_gives_t_at_the_threshold():
    rng = random.Random(5)
    a = [rng.gauss(1000, 40) for _ in range(5000)]
    b = [rng.gauss(1003, 90) for _ in range(7000)]
    na, ma, va = moments(a)
    nb, mb, vb = moments(b)
    _, se = timing.welch(na, ma, va, nb, mb, vb)
    mde = timing.T_THRESHOLD * se
    shifted = [x + ma + mde - mb for x in b]
    ns, ms, vs = moments(shifted)
    t, _ = timing.welch(na, ma, va, ns, ms, vs)
    assert t == pytest.approx(timing.T_THRESHOLD, rel=1e-9)
    assert timing.mde80(mde) == pytest.approx(mde * (4.5 + 0.8416212335729143) / 4.5)
    assert 0.5 * math.erfc(-timing.Z_POWER_80 / math.sqrt(2)) == pytest.approx(0.8, abs=1e-12)


def test_the_shift_sensitivity_of_a_uniform_crop_at_its_median_is_one_half():
    values = [i % 10_000 for i in range(200_000)]
    result = synth(values[::2], values[1::2])
    median_row = 10  # dudect's tenth percentile is exactly 0.5
    assert result["crops"]["threshold"][median_row] == 5_000
    assert result["crops"]["sensitivity"][median_row] == pytest.approx(0.5, abs=0.01)
    assert result["crops"]["sensitivity"][0] == 1.0


def test_verdicts_leak_pass_and_inconclusive_power():
    rng = random.Random(7)
    null = synth(gaussian(rng, 20_000, 1000, 20), gaussian(rng, 20_000, 1000, 20))
    rec = settle(null)
    assert rec.verdict == timing.PASS and not rec.problems, rec.problems
    assert rec.max_abs_t < timing.T_THRESHOLD
    assert rec.mde80_fraction < 0.01

    leak = synth(gaussian(rng, 20_000, 1000, 20), gaussian(rng, 20_000, 1004, 20))
    rec = settle(leak)
    assert rec.verdict == timing.LEAK and not rec.problems
    assert rec.max_abs_t > 10

    weak = synth(gaussian(rng, 1_500, 1000, 300), gaussian(rng, 1_500, 1000, 300))
    rec = settle(weak)
    assert rec.verdict == timing.INCONCLUSIVE and not rec.problems
    assert rec.mde80_fraction > 0.01


def test_recompute_flags_a_binary_result_that_disagrees():
    rng = random.Random(11)
    result = synth(gaussian(rng, 5_000, 800, 15), gaussian(rng, 5_000, 800, 15))
    assert not settle(result).problems
    tampered = json.loads(json.dumps(result))
    tampered["crops"]["t"][40] = (tampered["crops"]["t"][40] or 0) + 1.0
    assert any("row 40: t" in p for p in timing.recompute(tampered, 0.01).problems)
    tampered = json.loads(json.dumps(result))
    tampered["verdict"] = timing.LEAK
    assert any("binary verdict" in p for p in timing.recompute(tampered, 0.01).problems)
    tampered = json.loads(json.dumps(result))
    tampered["histogram"]["fixed"][3] += 1
    assert any("histogram" in p for p in timing.recompute(tampered, 0.01).problems)


def test_an_atom_of_identical_readings_backs_no_power_claim():
    # Every reading identical: zero variance must not read as infinite power.
    result = synth([500] * 3_000, [500] * 3_000)
    result["reading_quantum"] = 2
    rec = timing.recompute(result, 0.01)
    assert rec.headline_row is None and rec.verdict == timing.INCONCLUSIVE


def test_control_outcomes():
    assert timing.expected("leak", timing.LEAK) == "ok"
    assert timing.expected("leak", timing.PASS) == "blind"
    assert timing.expected("leak", timing.INCONCLUSIVE) == "blind"
    assert timing.expected("null", timing.LEAK) == "biased"
    assert timing.expected("null", timing.PASS) == "ok"
    assert timing.expected("constant_time", timing.LEAK) == "leak"
    assert timing.expected("constant_time", timing.INCONCLUSIVE) == "inconclusive"
    assert timing.expected("constant_time", timing.PASS) == "ok"


def test_report_dump_is_json_with_scalar_arrays_inline():
    value = {"a": [1, 2.5, None], "b": [{"c": "x"}], "d": {}}
    text = timing.dump(value)
    assert json.loads(text) == value
    assert '"a": [1, 2.5, null]' in text


def _valgrind_cases() -> dict[str, dict]:
    source = (AUDIT_SRC / "main.rs").read_text(encoding="utf-8")
    table = source[source.index("const CASES: &[Case] = &[") :]
    pattern = r"Case \{\s*name: \"([a-z0-9_]+)\",\s*expect: Expect::(\w+),\s*covers: &\[([^\]]*)\]"
    cases = {m.group(1): {"expect": m.group(2), "covers": re.findall(r"\"([^\"]+)\"", m.group(3))}
             for m in re.finditer(pattern, table)}
    # Every Case entry must parse, whatever expectation it declares.
    assert len(cases) == len(re.findall(r"\bCase \{", table)), "a Valgrind case did not parse"
    assert {c["expect"] for c in cases.values()} <= {"Clean", "Uniform", "Flagged"}
    return cases


def _timing_targets() -> dict[str, dict]:
    source = (AUDIT_SRC / "timing.rs").read_text(encoding="utf-8")
    table = source[source.index("pub(crate) const TARGETS: &[Target] = &[") :]
    pattern = r"Target \{\s*name: \"([a-z0-9_]+)\",\s*expect: Expect::(\w+),\s*covers: &\[([^\]]*)\]"
    targets = {}
    for m in re.finditer(pattern, table):
        assert m.group(1) not in targets, f"duplicate timing target {m.group(1)}"
        targets[m.group(1)] = {"expect": m.group(2), "covers": re.findall(r"\"([^\"]+)\"", m.group(3))}
    assert len(targets) == len(re.findall(r"\bTarget \{", table)), "a timing target did not parse"
    assert {t["expect"] for t in targets.values()} <= {"ConstantTime", "Leak", "Null"}
    return targets


def test_timing_targets_qualify_every_valgrind_case_behind_a_timing_site():
    cases = _valgrind_cases()
    targets = _timing_targets()
    assert cases and len(targets) >= 20
    covered = {c for t in targets.values() for c in t["covers"]}
    for name, target in targets.items():
        for case in target["covers"]:
            assert cases.get(case, {}).get("expect") in ("Clean", "Uniform"), f"{name} covers {case}"
        if target["expect"] != "ConstantTime":
            assert not target["covers"], f"control {name} must cover nothing"
    behind_sites = {
        name for name, case in cases.items() if case["expect"] in ("Clean", "Uniform") and case["covers"]
    }
    assert behind_sites, "no Valgrind case names a timing site; the parser is blind"
    assert behind_sites <= covered, sorted(behind_sites - covered)
    # The residual Memcheck cannot see is qualified for these too.
    assert {"threshold_gf_inv", "threshold_share_byte"} <= covered
    kinds = [t["expect"] for t in targets.values()]
    assert kinds.count("Leak") >= 2 and kinds.count("Null") >= 1
