"""Build-time properties of the native workspace that production relies on."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"


def _toml(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def test_a_native_panic_does_not_abort_the_daemon() -> None:
    # The extension is loaded into the daemon process and parses network
    # input. With panic = "abort", one out-of-range index anywhere in it is a
    # remote kill switch for the whole daemon. With "unwind", PyO3 raises
    # PanicException in the calling task and tokio isolates the failing task.
    release = _toml(NATIVE / "Cargo.toml")["profile"]["release"]
    assert release["panic"] == "unwind"


def test_constant_time_audit_profile_still_inherits_release() -> None:
    # The audit has to judge the code generation that ships.
    profile = _toml(NATIVE / "Cargo.toml")["profile"]["ct-audit"]
    assert profile["inherits"] == "release"
    assert "panic" not in profile


def test_one_tls_crypto_backend_is_compiled_in() -> None:
    deps = _toml(NATIVE / "Cargo.toml")["workspace"]["dependencies"]
    assert "rustls-ring" in deps["quinn"]["features"]
    assert "rustls-aws-lc-rs" not in deps["quinn"]["features"]
    assert "ring" in deps["rustls"]["features"]
    locked = {pkg["name"] for pkg in _toml(NATIVE / "Cargo.lock")["package"]}
    assert "ring" in locked
    assert not {name for name in locked if name.startswith("aws-lc")}


def test_kem_secrets_are_wiped() -> None:
    deps = _toml(NATIVE / "ol_pqkem" / "Cargo.toml")["dependencies"]
    assert "zeroize" in deps["ml-kem"]["features"]
    assert "zeroize" in deps["hybrid-array"]["features"]
    assert "zeroize" in deps["blake3"]["features"]
    source = (NATIVE / "ol_pqkem" / "src" / "hybrid.rs").read_text(encoding="utf-8")
    # The combiner streams its inputs; it must not rebuild the heap buffer
    # that used to hold both shared secrets unwiped.
    combine = source[source.index("fn combine(") : source.index("#[cfg(test)]")]
    assert "Vec::with_capacity" not in combine
    assert "new_derive_key(COMBINER_CONTEXT)" in combine


def test_received_encapsulation_keys_are_range_checked() -> None:
    source = (NATIVE / "ol_pqkem" / "src" / "hybrid.rs").read_text(encoding="utf-8")
    from_bytes = source[source.index("impl HybridPublicKey") : source.index("/// Hybrid secret key")]
    assert "encapsulation_key_is_reduced(&ml_kem_ek_bytes)" in from_bytes
    assert "InvalidEncapsulationKey" in from_bytes


def test_constant_time_evidence_records_the_profile_in_the_manifest() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_ct_timing_under_test", ROOT / "scripts" / "run_ct_timing.py"
    )
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        assert "panic=unwind" in module.ct_profile_description()
    finally:
        sys.modules.pop(spec.name, None)
