"""Runtime build identity for launcher/backend compatibility checks."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
import struct
import types
from pathlib import Path


_FINGERPRINT_FILES = (
    "__init__.py",
    "app.py",
    "cli.py",
    "daemon.py",
    "server.py",
    "state.py",
    "personal_device_mesh.py",
    "self_mesh_enrollment.py",
    "web/index.html",
)


# Stable standalone builds intentionally exclude the research/preview ML stack
# in ``scripts/build_binary.py``.  Everything else in the tuple below is a
# release contract, not a best-effort discovery result: a frozen bundle is
# incomplete if even one entry cannot be resolved from its own PyInstaller
# runtime root.  Keep this list explicit so a verifier cannot authenticate a
# self-consistent but accidentally stripped artifact.
STABLE_RUNTIME_EXCLUDED_MODULES = frozenset(
    {
        "one_link.call_reliability_soak",
        "one_link.neural_extrapolator",
        "one_link.perf_lab",
        "one_link.perf_lab_native",
        "one_link.semantic_scene_codec",
        "one_link.semantic_voice_codec",
        "one_link.transfer_sim",
    }
)
STABLE_RUNTIME_EXCLUDED_PREFIXES = ("one_link.ml",)
STABLE_RUNTIME_FORBIDDEN_MODULES: tuple[str, ...] = (
    "one_link.call_reliability_soak",
    "one_link.ml",
    "one_link.neural_extrapolator",
    "one_link.perf_lab",
    "one_link.perf_lab_native",
    "one_link.semantic_scene_codec",
    "one_link.semantic_voice_codec",
    "one_link.transfer_sim",
    "onnxruntime",
)

# One authoritative frozen-distribution boundary is consumed by both the
# builder and the independent release validator.  Keeping this list here
# prevents the two programs from drifting into the dangerous state where the
# builder stops excluding a dependency but the validator still believes that
# it did (or vice versa).  Prefix semantics are intentional: excluding
# ``pytest`` also excludes every pytest plug-in submodule.
STABLE_FROZEN_EXCLUDED_MODULE_PREFIXES: tuple[str, ...] = tuple(
    sorted(
        {
            "IPython",
            "aiohttp.pytest_plugin",
            "aiohttp.test_utils",
            "aiohttp.worker",
            "annotated_types",
            "ast_serialize",
            "certifi",
            "cffi._shimmed_dist_utils",
            "cffi.ffiplatform",
            "cffi.recompiler",
            "cffi.setuptools_ext",
            "cffi.verifier",
            "cffi.vengine_cpy",
            "cffi.vengine_gen",
            "charset_normalizer",
            "cupy",
            "email_validator",
            "hypothesis",
            "id",
            "jax",
            "jaxlib",
            "jupyter",
            "jwt",
            "llvmlite",
            "lxml",
            "markdown_it",
            "matplotlib",
            "mdurl",
            "mypy",
            "mypy_extensions",
            "notebook",
            "numba",
            "numpy",
            "nvidia",
            "onnxruntime",
            "one_link.call_reliability_soak",
            "one_link.ml",
            "one_link.neural_extrapolator",
            "one_link.perf_lab",
            "one_link.perf_lab_native",
            "one_link.semantic_scene_codec",
            "one_link.semantic_voice_codec",
            "one_link.transfer_sim",
            "pandas",
            "pyasn1",
            "pydantic",
            "pydantic_core",
            "pygments",
            "pytest",
            "rekor_types",
            "requests",
            "rfc3161_client",
            "rfc8785",
            "rich",
            "scipy",
            "securesystemslib",
            "setuptools",
            "sigstore",
            "sigstore_models",
            "sympy",
            "tensorflow",
            "tensorflow_intel",
            "test",
            "tests",
            "torch",
            "torchaudio",
            "torchvision",
            "tuf",
            "typing_inspection",
            "urllib3",
            "wheel",
        }
    )
)

# Every non-stdlib Python namespace admitted to a stable frozen application is
# reviewed here.  The validator combines this set with the stdlib of the
# validation interpreter and the two legacy 3.12 stdlib roots below.  A new
# dependency therefore fails release validation until its runtime necessity is
# explicit and reviewed, instead of silently becoming executable release code.
STABLE_FROZEN_ALLOWED_THIRD_PARTY_ROOTS = frozenset(
    {
        "AppKit",  # pyobjc / pystray on macOS
        "CoreFoundation",
        "Foundation",
        # pyobjc's pure-Python helper package (KeyValueCoding, AppHelper...)
        # ships alongside the objc/AppKit roots already reviewed above; the
        # first macOS release bundle ever gated surfaced it in the PYZ.
        "PyObjCTools",
        "OpenSSL",
        "PIL",
        "Quartz",
        "SecretStorage",  # historical Linux Secret Service import spelling
        "Xlib",  # pystray Xorg backend
        "_cffi_backend",
        "aiohappyeyeballs",
        "aiohttp",
        "aioice",
        "aiortc",
        "aiosignal",
        "attr",
        "attrs",
        "av",
        "backports",
        "blake3",
        "cffi",
        "click",
        "colorama",
        "cryptography",
        "dns",
        "frozenlist",
        "google_crc32c",
        "idna",
        "ifaddr",
        "importlib_metadata",
        "jaraco",
        "jeepney",
        "keyring",
        "librt",
        "more_itertools",
        "multidict",
        "objc",
        "one_link_native",
        "packaging",
        "platformdirs",
        "propcache",
        "psutil",
        "pycparser",
        "pyee",
        "pylibsrtp",
        "pystray",
        "qrcode",
        "secretstorage",
        "six",
        "sqlcipher3",
        "typing_extensions",
        "watchdog",
        "win32ctypes",
        "yarl",
        "zeroconf",
        "zipp",
    }
)
STABLE_FROZEN_LEGACY_STDLIB_ROOTS = frozenset({"_compression", "cgi"})

# Excluded top-level distributions that must not leave compiled libraries,
# metadata, or other non-Python residue in an onedir tree.  Nested exclusions
# below an otherwise required root (for example ``cffi.recompiler`` and
# ``aiohttp.test_utils``) are deliberately omitted here: their Python modules
# remain governed by the exact PYZ contract, while the parent runtime package
# is still allowed.  One Link's own excluded modules are likewise checked by
# the exact application namespace gate.
STABLE_FROZEN_FORBIDDEN_PHYSICAL_ROOTS = frozenset(
    prefix.split(".", 1)[0].casefold()
    for prefix in STABLE_FROZEN_EXCLUDED_MODULE_PREFIXES
    if prefix.split(".", 1)[0] not in STABLE_FROZEN_ALLOWED_THIRD_PARTY_ROOTS
    and prefix.split(".", 1)[0] != "one_link"
)

# Fail-closed resource ceilings for release candidates.  These are well above
# the current onedir footprint, but low enough to catch accidental model/test
# graph inclusion, archive bombs, and a duplicated launcher/runtime tree.
STABLE_FROZEN_MAX_FILES = 12_000
STABLE_FROZEN_MAX_DIRECTORIES = 4_096
STABLE_FROZEN_MAX_ENTRIES = 16_000
STABLE_FROZEN_MAX_BUNDLE_BYTES = 768 * 1024 * 1024
STABLE_FROZEN_MAX_PYZ_MODULES = 4_096
STABLE_FROZEN_MAX_ZIP_MEMBERS = 12_000
STABLE_FROZEN_MAX_ZIP_UNCOMPRESSED_BYTES = 256 * 1024 * 1024

# Exact non-Python payload served or consumed by every stable Python and
# standalone installation. Native libraries are deliberately absent: the core
# wheel is universal, the optional Rust package has its own wheel contract,
# and PyInstaller builds stage a freshly compiled CDC library separately.
EXPECTED_STABLE_PACKAGE_DATA: tuple[str, ...] = (
    "data/bip39-english.txt",
    "data/certified/link_badge.json",
    "data/certified/origin_fence.json",
    "data/certified/peer_row.json",
    "data/certified/unread_badge.json",
    "data/oui_prefixes.txt.gz",
    "web/assets/argon2id-v1.wasm",
    "web/assets/argon2id-worker.js",
    "web/assets/ed25519-v1.wasm",
    "web/assets/one-glyph-128.png",
    "web/assets/one-glyph-256.png",
    "web/assets/one-glyph-512.png",
    "web/assets/one-glyph-app.png",
    "web/assets/one-glyph.ico",
    "web/assets/one-glyph.png",
    "web/assets/one-link-app.ico",
    "web/assets/one-link-black.ico",
    "web/dr.js",
    "web/dr_test.html",
    "web/index.html",
    "web/manifest.json",
    "web/peer.html",
    "web/sw.js",
)

# The native package exposes 33 registered submodules plus its package root,
# matching the 34 public ``.pyi`` surfaces shipped by its wheel. Fully
# qualified names make this tuple directly usable by isolated import probes.
EXPECTED_NATIVE_RUNTIME_SUBMODULES: tuple[str, ...] = (
    "one_link_native.aead",
    "one_link_native.align",
    "one_link_native.bandit",
    "one_link_native.bloom",
    "one_link_native.capability",
    "one_link_native.chunk",
    "one_link_native.coherence_field",
    "one_link_native.compress",
    "one_link_native.confidential",
    "one_link_native.crdt",
    "one_link_native.discovery",
    "one_link_native.erasure",
    "one_link_native.fec",
    "one_link_native.fountain",
    "one_link_native.fuse",
    "one_link_native.homology",
    "one_link_native.hwkey",
    "one_link_native.obfs",
    "one_link_native.onion",
    "one_link_native.pair_qr",
    "one_link_native.pqkem",
    "one_link_native.pqsig",
    "one_link_native.prefetch",
    "one_link_native.proximity_pair",
    "one_link_native.quic",
    "one_link_native.radio_batcher",
    "one_link_native.ratchet",
    "one_link_native.routing",
    "one_link_native.selector",
    "one_link_native.sphinx",
    "one_link_native.store",
    "one_link_native.threshold_recovery",
    "one_link_native.wal",
)

# Package modules map to ``__init__.py`` rather than ``<name>.py``. Keeping
# that distinction explicit makes source/archive parity deterministic and
# avoids probing the filesystem to infer release structure.
STABLE_RUNTIME_PACKAGE_MODULES = frozenset(
    {
        "one_link",
        "one_link.transport_adapters",
    }
)
EXPECTED_STABLE_RUNTIME_MODULES: tuple[str, ...] = (
    "one_link",
    "one_link.__main__",
    "one_link._coerce",
    "one_link.aead_native",
    "one_link.align_native",
    "one_link.app",
    "one_link.async_capsule",
    "one_link.autostart",
    "one_link.backup_bundle",
    "one_link.bandit_native",
    "one_link.beacon",
    "one_link.beacon_listener",
    "one_link.blobstore",
    "one_link.bloom_init",
    "one_link.bloom_native",
    "one_link.body_engine",
    "one_link.bounded_resolver",
    "one_link.build_identity",
    "one_link.build_info",
    "one_link.call_api",
    "one_link.call_immune",
    "one_link.call_immune_actions",
    "one_link.call_immune_runtime",
    "one_link.call_manager",
    "one_link.call_reliability",
    "one_link.call_sdp_signaling",
    "one_link.call_session",
    "one_link.call_signaling",
    "one_link.call_vitals",
    "one_link.cap_migration",
    "one_link.cap_root_key",
    "one_link.cap_store",
    "one_link.capabilities",
    "one_link.capability_native",
    "one_link.caps_grants",
    "one_link.capsule_at_rest",
    "one_link.capsule_store",
    "one_link.capsule_transport",
    "one_link.cdc",
    "one_link.certified_surface",
    "one_link.channel",
    "one_link.chat",
    "one_link.chunk_cache_gc",
    "one_link.chunk_native",
    "one_link.chunk_ratchet",
    "one_link.chunk_store_native",
    "one_link.cli",
    "one_link.coherence_field_native",
    "one_link.compress_native",
    "one_link.confidential_native",
    "one_link.control_ipc",
    "one_link.conversation_object",
    "one_link.courier_bundle",
    "one_link.cover_traffic",
    "one_link.crash_log",
    "one_link.crdt",
    "one_link.crdt_native",
    "one_link.crossfade",
    "one_link.daemon",
    "one_link.debug_log",
    "one_link.dedupe_sites",
    "one_link.deletion_chain",
    "one_link.device_guardian",
    "one_link.device_info",
    "one_link.device_relogin",
    "one_link.dht",
    "one_link.dht_vrf_routing",
    "one_link.discovery",
    "one_link.discovery_native",
    "one_link.double_ratchet",
    "one_link.durability",
    "one_link.env_bounds",
    "one_link.erasure_native",
    "one_link.error_dialog",
    "one_link.fault_observability",
    "one_link.fec_native",
    "one_link.field_observations_native",
    "one_link.field_snapshot",
    "one_link.folder_native",
    "one_link.foldersync",
    "one_link.fountain",
    "one_link.fountain_native",
    "one_link.frame_provenance",
    "one_link.fuse_native",
    "one_link.group_invite",
    "one_link.groups",
    "one_link.groups_crypto",
    "one_link.handoff_orchestrator",
    "one_link.handshake_attestation",
    "one_link.hardening_checks",
    "one_link.hardware_inventory",
    "one_link.homology_native",
    "one_link.hwkey_native",
    "one_link.identity",
    "one_link.identity_dag",
    "one_link.identity_rotation",
    "one_link.identity_sas",
    "one_link.key_material",
    "one_link.keychain",
    "one_link.lan_discovery",
    "one_link.live_frame_provenance",
    "one_link.local_stun",
    "one_link.lockbox",
    "one_link.master_seed",
    "one_link.merkle",
    "one_link.mls_treekem",
    "one_link.mnemonic",
    "one_link.mobile_reach",
    "one_link.namespace_durability",
    "one_link.native_cdc",
    "one_link.native_transfer",
    "one_link.obfs_native",
    "one_link.onion",
    "one_link.onion_native",
    "one_link.pacing",
    "one_link.pair_qr_native",
    "one_link.pairing",
    "one_link.path_pii",
    "one_link.paths",
    "one_link.peer_https",
    "one_link.peer_quic",
    "one_link.peer_rtc",
    "one_link.peer_transport",
    "one_link.personal_device_mesh",
    "one_link.platform_guard",
    "one_link.pq_hybrid",
    "one_link.pqkem_native",
    "one_link.pqsig_native",
    "one_link.predictive_continuity",
    "one_link.predictive_continuity_runtime",
    "one_link.prefetch_native",
    "one_link.presence_compiler",
    "one_link.priority_engine",
    "one_link.process_security",
    "one_link.protocol_compat",
    "one_link.protocol_handler",
    "one_link.provenance_wiring",
    "one_link.proximity_pair_native",
    "one_link.psi",
    "one_link.quic_native",
    "one_link.radio_batcher_native",
    "one_link.ratchet_native",
    "one_link.rdz_blind",
    "one_link.recording_consent",
    "one_link.recovery_api",
    "one_link.relay_client",
    "one_link.relay_proto",
    "one_link.relay_routing",
    "one_link.removable_media",
    "one_link.rendezvous_client",
    "one_link.rendezvous_proto",
    "one_link.rendezvous_server",
    "one_link.replay_window",
    "one_link.resume",
    "one_link.ring_sig",
    "one_link.route_bootstrap",
    "one_link.route_brain",
    "one_link.routing_native",
    "one_link.safe_http",
    "one_link.sealed_relay",
    "one_link.sealed_sender",
    "one_link.selector_native",
    "one_link.self_mesh_enrollment",
    "one_link.server",
    "one_link.sessions",
    "one_link.share_link",
    "one_link.sigstore_verify",
    "one_link.social_recovery",
    "one_link.sovereign",
    "one_link.sovereignty",
    "one_link.sphinx_native",
    "one_link.splash",
    "one_link.standalone_updater",
    "one_link.state",
    "one_link.state_encryption",
    "one_link.storage_lifecycle",
    "one_link.supervisor",
    "one_link.swarm_plan",
    "one_link.threshold",
    "one_link.threshold_recovery_native",
    "one_link.traffic_shaper",
    "one_link.transfer_brain",
    "one_link.transfer_doctor",
    "one_link.transfer_intent",
    "one_link.transfer_safety",
    "one_link.transport_activation",
    "one_link.transport_adapters",
    "one_link.transport_adapters.base",
    "one_link.transport_adapters.onefield",
    "one_link.transport_adapters.route_memory",
    "one_link.transport_adapters.static",
    "one_link.transport_adapters.tcp",
    "one_link.transport_fabric",
    "one_link.transport_path_creation",
    "one_link.transport_priority",
    "one_link.tray",
    "one_link.trust_ledger",
    "one_link.ui_delivery_idempotency",
    "one_link.update_check",
    "one_link.update_helper",
    "one_link.update_metadata",
    "one_link.update_transaction",
    "one_link.updater",
    "one_link.vrf",
    "one_link.wal_native",
    "one_link.wave_forecast_native",
    "one_link.wire",
)


def stable_runtime_manifest_sha256(
    modules: tuple[str, ...] = EXPECTED_STABLE_RUNTIME_MODULES,
) -> str:
    """Return a framed digest of the exact ordered stable-module contract."""
    digest = hashlib.sha256(b"ONE-LINK-STABLE-RUNTIME-MODULES-V1\x00")
    for module in modules:
        encoded = module.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


EXPECTED_STABLE_RUNTIME_MODULES_SHA256 = stable_runtime_manifest_sha256()


def stable_package_data_manifest_sha256(
    paths: tuple[str, ...] = EXPECTED_STABLE_PACKAGE_DATA,
) -> str:
    """Return a framed digest of the ordered stable package-data contract."""
    digest = hashlib.sha256(b"ONE-LINK-STABLE-PACKAGE-DATA-V1\x00")
    for path in paths:
        encoded = path.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


EXPECTED_STABLE_PACKAGE_DATA_SHA256 = stable_package_data_manifest_sha256()


def native_runtime_submodule_manifest_sha256(
    modules: tuple[str, ...] = EXPECTED_NATIVE_RUNTIME_SUBMODULES,
) -> str:
    """Return a framed digest of the ordered native-extension ABI surface."""
    digest = hashlib.sha256(b"ONE-LINK-NATIVE-RUNTIME-SUBMODULES-V1\x00")
    for module in modules:
        encoded = module.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


EXPECTED_NATIVE_RUNTIME_SUBMODULES_SHA256 = native_runtime_submodule_manifest_sha256()


def stable_module_source_path(package_root: Path, module: str) -> Path:
    """Map one explicit stable module to its canonical source path.

    The result is purely derived from the contract and *package_root*; callers
    decide whether the path exists and whether its bytes match an artifact.
    """
    if module not in EXPECTED_STABLE_RUNTIME_MODULES:
        raise ValueError(f"module is outside the stable runtime contract: {module}")
    if module == "one_link":
        relative_parts: tuple[str, ...] = ()
    else:
        prefix = "one_link."
        if not module.startswith(prefix):
            raise ValueError(f"invalid One Link runtime module: {module}")
        relative_parts = tuple(module[len(prefix) :].split("."))
    if module in STABLE_RUNTIME_PACKAGE_MODULES:
        return package_root.joinpath(*relative_parts, "__init__.py")
    return package_root.joinpath(*relative_parts).with_suffix(".py")


def _framed_code_value(tag: bytes, payload: bytes) -> bytes:
    return tag + len(payload).to_bytes(8, "big") + payload


def _canonical_code_value(value: object) -> bytes:
    """Encode code metadata without marshal's object-reference side effects."""
    if value is None:
        return _framed_code_value(b"N", b"")
    if value is Ellipsis:
        return _framed_code_value(b"E", b"")
    if isinstance(value, bool):
        return _framed_code_value(b"B", b"1" if value else b"0")
    if isinstance(value, int):
        return _framed_code_value(b"I", str(value).encode("ascii"))
    if isinstance(value, float):
        return _framed_code_value(b"F", struct.pack(">d", value))
    if isinstance(value, complex):
        return _framed_code_value(
            b"J",
            struct.pack(">dd", value.real, value.imag),
        )
    if isinstance(value, str):
        return _framed_code_value(b"S", value.encode("utf-8", "surrogatepass"))
    if isinstance(value, bytes):
        return _framed_code_value(b"Y", value)
    # Python 3.14 can intern literal subscription slices directly in
    # ``co_consts``. Treat all three components as recursively framed code
    # constants so build identity remains deterministic across source paths.
    if isinstance(value, slice):
        return _framed_code_value(
            b"L",
            _canonical_code_value((value.start, value.stop, value.step)),
        )
    if isinstance(value, tuple):
        payload = len(value).to_bytes(8, "big") + b"".join(
            _canonical_code_value(item) for item in value
        )
        return _framed_code_value(b"T", payload)
    if isinstance(value, frozenset):
        items = sorted(_canonical_code_value(item) for item in value)
        payload = len(items).to_bytes(8, "big") + b"".join(items)
        return _framed_code_value(b"R", payload)
    if isinstance(value, types.CodeType):
        # co_filename is intentionally excluded: PyInstaller rewrites build
        # paths while preserving the executable program. Every semantic and
        # debugging field that remains is framed in a fixed order.
        fields: tuple[object, ...] = (
            value.co_argcount,
            value.co_posonlyargcount,
            value.co_kwonlyargcount,
            value.co_nlocals,
            value.co_stacksize,
            value.co_flags,
            value.co_code,
            value.co_consts,
            value.co_names,
            value.co_varnames,
            value.co_freevars,
            value.co_cellvars,
            value.co_name,
            value.co_qualname,
            value.co_firstlineno,
            value.co_linetable,
            value.co_exceptiontable,
        )
        return _framed_code_value(b"C", _canonical_code_value(fields))
    raise TypeError(
        "unsupported constant in Python code object: "
        f"{type(value).__module__}.{type(value).__qualname__}"
    )


def normalized_code_sha256(code: types.CodeType) -> str:
    """Hash executable code independently of source/build directory names.

    Nested code objects are encoded recursively. All semantic bytecode,
    constants, names, flags, line tables, and exception tables remain intact.
    Unlike ``marshal.dumps``, this encoding does not vary based on string
    interning or reference-sharing choices made by a pyc/PYZ loader.
    """
    if not isinstance(code, types.CodeType):
        raise TypeError("code must be a types.CodeType instance")
    payload = _canonical_code_value(code)
    digest = hashlib.sha256(b"ONE-LINK-NORMALIZED-CODE-V2\x00")
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def stable_forbidden_runtime_manifest_sha256(
    modules: tuple[str, ...] = STABLE_RUNTIME_FORBIDDEN_MODULES,
) -> str:
    """Return a framed digest of modules forbidden in stable bundles."""
    digest = hashlib.sha256(b"ONE-LINK-STABLE-FORBIDDEN-MODULES-V1\x00")
    for module in modules:
        encoded = module.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256 = stable_forbidden_runtime_manifest_sha256()


def package_root() -> Path:
    return Path(__file__).resolve().parent


def native_package_root() -> Path | None:
    """Locate the separately installed native-extension package, if present."""
    spec = importlib.util.find_spec("one_link_native")
    if spec is None or spec.submodule_search_locations is None:
        return None
    locations = tuple(spec.submodule_search_locations)
    if len(locations) != 1:
        return None
    return Path(locations[0]).resolve()


def stable_runtime_module_statuses(expected_root: Path) -> dict[str, str]:
    """Resolve every stable module and constrain it to *expected_root*.

    ``find_spec`` verifies that PyInstaller's importer can actually locate a
    module in its PYZ archive; a physical-file walk alone cannot prove that.
    The function deliberately does not import the target modules.  Status
    strings are stable protocol values because the install rollup binds them.
    """
    root = expected_root.resolve(strict=False)
    statuses: dict[str, str] = {}
    for module in EXPECTED_STABLE_RUNTIME_MODULES:
        try:
            spec = importlib.util.find_spec(module)
        except Exception:  # A broken/custom finder is an invalid install.
            statuses[module] = "SPEC_ERROR"
            continue
        if spec is None:
            statuses[module] = "MISSING"
            continue
        if spec.name != module:
            statuses[module] = "SPEC_NAME_MISMATCH"
            continue
        if spec.loader is None:
            statuses[module] = "MISSING_LOADER"
            continue
        origin = spec.origin
        if not origin or origin in {"built-in", "frozen"}:
            statuses[module] = "MISSING_ORIGIN"
            continue
        try:
            resolved_origin = Path(origin).resolve(strict=False)
            resolved_origin.relative_to(root)
        except (OSError, ValueError):
            statuses[module] = "OUTSIDE_EXPECTED_ROOT"
            continue
        get_code = getattr(spec.loader, "get_code", None)
        if not callable(get_code):
            statuses[module] = "MISSING_CODE_LOADER"
            continue
        try:
            code = get_code(module)
        except Exception:
            statuses[module] = "UNLOADABLE_CODE"
            continue
        if not isinstance(code, types.CodeType):
            statuses[module] = "MISSING_CODE"
            continue
        statuses[module] = "PRESENT"
    return statuses


def stable_forbidden_runtime_module_statuses(
    expected_root: Path,
) -> dict[str, str]:
    """Prove that preview-only modules cannot resolve in a stable bundle."""
    root = expected_root.resolve(strict=False)
    statuses: dict[str, str] = {}
    for module in STABLE_RUNTIME_FORBIDDEN_MODULES:
        try:
            spec = importlib.util.find_spec(module)
        except Exception:
            statuses[module] = "SPEC_ERROR"
            continue
        if spec is None:
            statuses[module] = "ABSENT"
            continue
        origin = spec.origin
        if not origin or origin in {"built-in", "frozen"}:
            statuses[module] = "PRESENT_UNKNOWN_ORIGIN"
            continue
        try:
            Path(origin).resolve(strict=False).relative_to(root)
        except (OSError, ValueError):
            statuses[module] = "PRESENT_OUTSIDE_BUNDLE"
        else:
            statuses[module] = "PRESENT_IN_BUNDLE"
    return statuses


def _is_link_like(path: Path) -> bool:
    """Return whether *path* is a symlink or Windows reparse point."""
    try:
        metadata = path.lstat()
    except OSError:
        # Keep the entry in the inventory.  The hashing pass will report the
        # exact access failure and fail closed.
        return False
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def installation_inventory_files(
    root: Path | None = None,
    *,
    include_all_files: bool = False,
) -> tuple[str, ...]:
    """Return every stable file under the installed ``one_link`` package.

    ``source_fingerprint`` intentionally uses a small latency-sensitive subset
    for launcher/daemon compatibility. Install verification needs the opposite
    trade-off: enumerate Python, native binaries, web assets, and packaged data
    so its rollup cannot silently ignore most of the application. Executable
    bytecode caches are included because Python may load them instead of source;
    source-tree callers exclude only inert OS metadata;
    ``include_all_files`` is for a frozen managed bundle where every physical
    file below the artifact root is part of the release identity.
    """
    base = (root or package_root()).resolve()
    entries: list[str] = []

    # Do not follow directory links.  A verifier that recursively follows an
    # attacker-controlled link can hash arbitrary files outside the install,
    # hang on cycles, or produce a machine-specific baseline.  Link entries are
    # nevertheless returned so the caller can reject them explicitly.
    def _raise_walk_error(error: OSError) -> None:
        raise error

    for directory, directory_names, file_names in os.walk(
        base,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        directory_names.sort()
        file_names.sort()
        parent = Path(directory)
        for name in tuple(directory_names):
            path = parent / name
            if _is_link_like(path):
                entries.append(path.relative_to(base).as_posix())
                directory_names.remove(name)
        for name in file_names:
            path = parent / name
            relative = path.relative_to(base)
            if not include_all_files:
                if path.name in {".DS_Store", "Thumbs.db"}:
                    continue
            entries.append(relative.as_posix())
    return tuple(sorted(entries))


def source_fingerprint() -> str:
    """Hash files that must match between launcher, UI, and daemon.

    Dev builds often keep the same semantic version while source changes
    quickly. This lets the desktop launcher reject stale background daemons
    even when ``one_link.__version__`` did not move.
    """
    root = package_root()
    h = hashlib.blake2s(digest_size=16)
    for rel in _FINGERPRINT_FILES:
        path = root / rel
        h.update(rel.encode("utf-8"))
        try:
            st = path.stat()
        except OSError:
            h.update(b":missing")
            continue
        h.update(str(st.st_size).encode("ascii"))
        h.update(str(st.st_mtime_ns).encode("ascii"))
    return h.hexdigest()


def runtime_build_identity() -> dict[str, str]:
    return {
        "package_root": str(package_root()),
        "source_fingerprint": source_fingerprint(),
    }
