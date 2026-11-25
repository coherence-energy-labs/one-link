//! Deterministic secret-dependence audit of One Link's constant-time code.
//!
//! Each case marks its secret inputs as undefined for Valgrind Memcheck and
//! calls the production function. Memcheck then reports every conditional
//! branch and every memory address that depends on a secret, in the code the
//! compiler actually emitted for the release profile. Unlike the wall-clock
//! `timing_gate!` tests this does not sample anything, so it is not noisy:
//! the same binary gives the same verdict on a shared CI runner and on a
//! quiet machine.
//!
//! A verdict that a function exists to compute (accept/reject, real/duress)
//! is public by design. Production code marks the one line where such a
//! verdict is branched on with a `ct-audit: declassify` comment, and the
//! driver (`scripts/run_ct_audit.py`) accepts a report only when its
//! innermost source line carries that marker. Any other report fails.
//!
//! Negative controls (`Expect::Flagged`) are known-leaky code, including the
//! production `gf_mul_fast` documented as not constant-time. They must be
//! reported; if they are not, the instrument is blind and the audit fails.
//!
//! Limits, stated so they are not mistaken for coverage: Memcheck does not
//! model variable-latency instructions (integer division, some
//! microarchitectural effects), and it audits this binary's code generation,
//! not every other build of the same source. The controlled-runner timing
//! study covers the former.
//!
//! Usage: `ol_ct_audit --list` prints one JSON object per case;
//! `ol_ct_audit <case>` runs one case and must run under Valgrind
//! (`--native-smoke` runs it natively, as a functional check only).

mod valgrind;

use std::fmt::Write as _;
use std::hint::black_box;
use std::process::ExitCode;

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use valgrind::{declassify, error_count, mark_secret, public, running_on_valgrind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// No undeclassified secret-dependent branch or address may be reported.
    Clean,
    /// Known-leaky control: at least one report is required.
    Flagged,
}

#[derive(Debug)]
struct Case {
    name: &'static str,
    expect: Expect,
    /// Timing-gate sites (`<crate>/tests/<file>.rs::<fn>`) whose secret
    /// dataflow this case audits.
    covers: &'static [&'static str],
    what: &'static str,
    run: fn(),
}

/// Deterministic bytes the optimiser cannot see through: the seed passes
/// through `black_box`, so nothing derived from it is a compile-time constant.
fn bytes<const N: usize>(stream: u64) -> [u8; N] {
    let mut state =
        black_box(0x6f6c_5f63_745f_6175_u64) ^ stream.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut out = [0u8; N];
    for chunk in out.chunks_mut(8) {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let word = z.to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    out
}

fn rng(stream: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(black_box(0x6374_6175_6469_7400 ^ stream))
}

// ---------------------------------------------------------------- controls

#[inline(never)]
fn control_side_effect(value: u8) -> u8 {
    black_box(value.rotate_left(3) ^ 0x5a)
}

fn control_branch_on_secret() {
    let secret: [u8; 4] = bytes(1);
    mark_secret(&secret);
    let s = black_box(&secret);
    let mut acc = 0u8;
    for &b in s {
        // A data-dependent branch around a call cannot be turned into a cmov.
        if b & 1 == 1 {
            acc ^= control_side_effect(b);
        }
    }
    black_box(public(acc));
}

fn control_secret_table_index() {
    // Production code documented as NOT constant-time: a 64 KiB lookup table
    // indexed by its operands. It must be reported.
    let secret: [u8; 2] = bytes(2);
    mark_secret(&secret);
    let s = black_box(&secret);
    let product = ol_threshold_recovery::gf_mul_fast(s[0], s[1]);
    black_box(public(product));
}

fn control_short_circuit_zero_test() {
    // The pattern this audit found in ol_onion's small-order checks: an
    // iterator `all` stops at the first non-zero byte of a shared secret.
    let secret: [u8; 32] = bytes(3);
    mark_secret(&secret);
    let s = black_box(&secret);
    let all_zero = s.iter().all(|&b| b == 0);
    black_box(public(all_zero));
}

// ------------------------------------------------------- threshold recovery

fn threshold_gf_mul() {
    let secret: [u8; 64] = bytes(10);
    mark_secret(&secret);
    let s = black_box(&secret);
    let mut acc = 0u32;
    for pair in s.chunks_exact(2) {
        acc ^= ol_threshold_recovery::gf_mul(u32::from(pair[0]), u32::from(pair[1]));
    }
    black_box(public(acc));
}

fn threshold_gf_inv() {
    let secret: [u8; 16] = bytes(11);
    mark_secret(&secret);
    let s = black_box(&secret);
    let mut acc = 0u32;
    for &b in s {
        acc ^= ol_threshold_recovery::gf_inv(u32::from(b));
    }
    black_box(public(acc));
}

fn threshold_share_byte() {
    let secret: [u8; 8] = bytes(12);
    let mut prng = ol_threshold_recovery::PrngState::new(black_box(0x7365_6372_6574_u64));
    // The coefficient stream is as secret as the shared byte.
    mark_secret(&secret);
    mark_secret(&prng);
    let s = black_box(&secret);
    for &b in s {
        let shares =
            ol_threshold_recovery::share_byte(b, 3, 5, &mut prng).expect("valid parameters");
        black_box(&shares);
    }
}

// ------------------------------------------------------------------- onion

fn onion_hop_id_eq() {
    let secret: [u8; ol_onion::HOP_ID_LEN] = bytes(20);
    let probe: [u8; ol_onion::HOP_ID_LEN] = bytes(21);
    let mut near = secret;
    near[ol_onion::HOP_ID_LEN - 1] ^= 1;
    let a = ol_onion::HopId::from_bytes(secret);
    mark_secret(&a);
    let a = black_box(&a);
    let equal_probe = *a == ol_onion::HopId::from_bytes(probe);
    let equal_near = *a == ol_onion::HopId::from_bytes(near);
    black_box(public((equal_probe, equal_near)));
}

fn onion_layer_key_eq() {
    let secret: [u8; 32] = bytes(22);
    let mut near = secret;
    near[0] ^= 0x80;
    let a = ol_onion::keyderiv::LayerKey::from_bytes(secret);
    let b = ol_onion::keyderiv::LayerKey::from_bytes(near);
    mark_secret(&a);
    let equal = *black_box(&a) == b;
    black_box(public(equal));
}

fn onion_header_mac_verify() {
    use ol_onion::sphinx::primitives::{header_mac, verify_header_mac, HEADER_LEN};
    let key: [u8; 32] = bytes(23);
    let header = vec![0xcd_u8; HEADER_LEN];
    let good = header_mac(&key, &header);
    let mut bad = good;
    bad[7] ^= 1;
    mark_secret(&key);
    let k = black_box(&key);
    let ok_good = verify_header_mac(k, &header, &good);
    let ok_bad = verify_header_mac(k, &header, &bad);
    black_box(public((ok_good, ok_bad)));
}

fn onion_relay_layer_key() {
    use x25519_dalek::{PublicKey, StaticSecret};
    let relay = StaticSecret::from(bytes::<32>(24));
    let sender = StaticSecret::from(bytes::<32>(25));
    let sender_pk = PublicKey::from(&sender);
    mark_secret(&relay);
    let relay = black_box(&relay);
    let key = ol_onion::keyderiv::derive_layer_key_relay(relay, &sender_pk);
    black_box(&key);
    let shared = relay.diffie_hellman(&sender_pk);
    let small_order = ol_onion::keyderiv::is_zero_shared(&shared);
    black_box(public(small_order));
}

fn sphinx_circuit(
    hops: usize,
    stream: u64,
) -> (
    Vec<ol_onion::sphinx::SphinxHop>,
    Vec<curve25519_dalek::Scalar>,
) {
    let mut r = rng(stream);
    let mut circuit = Vec::with_capacity(hops);
    let mut secrets = Vec::with_capacity(hops);
    for i in 0..hops {
        let (sk, pk) = ol_onion::sphinx::generate_static_keypair(&mut r);
        let id_stream = stream + 100 + u64::try_from(i).expect("small");
        circuit.push(ol_onion::sphinx::SphinxHop {
            id: ol_onion::HopId::from_bytes(bytes(id_stream)),
            static_pk: pk,
        });
        secrets.push(sk);
    }
    (circuit, secrets)
}

fn sphinx_build() {
    let (circuit, _) = sphinx_circuit(3, 30);
    let mut r = rng(31);
    let (sender, _) = ol_onion::sphinx::generate_static_keypair(&mut r);
    mark_secret(&sender);
    let payload = bytes::<64>(32);
    let packet =
        ol_onion::sphinx::build_sphinx_onion(black_box(&sender), &circuit, &payload, &mut r)
            .expect("valid circuit");
    black_box(&packet);
}

fn sphinx_final_hop_key() {
    let (circuit, _) = sphinx_circuit(3, 33);
    let mut r = rng(34);
    let (sender, _) = ol_onion::sphinx::generate_static_keypair(&mut r);
    mark_secret(&sender);
    let key = ol_onion::sphinx::core::compute_final_hop_shared_key(black_box(&sender), &circuit)
        .expect("valid circuit");
    black_box(&key);
}

fn sphinx_peel() {
    let (circuit, secrets) = sphinx_circuit(3, 35);
    let mut r = rng(36);
    let (sender, _) = ol_onion::sphinx::generate_static_keypair(&mut r);
    let payload = bytes::<64>(37);
    let packet = ol_onion::sphinx::build_sphinx_onion(&sender, &circuit, &payload, &mut r)
        .expect("valid circuit");
    let relay = secrets[0];
    mark_secret(&relay);
    let outcome = ol_onion::sphinx::peel_sphinx_layer(black_box(&relay), &packet);
    black_box(&outcome);
}

fn obfs_server_accept() {
    use ol_onion::transport_obfs::handshake::{BridgeKeypair, ClientHandshake, ServerHandshake};
    let mut r = rng(40);
    let bridge = BridgeKeypair::from_parts(bytes(41), bytes(42));
    let bridge_pk = bridge.public_bytes();
    let bridge_id = bridge.id_bytes();
    let now = 1_700_000_000_u64;
    let client = ClientHandshake::start(&mut r, &bridge_pk, &bridge_id, now);
    let good = *client.first_message();
    let mut forged = good;
    forged[40] ^= 1;
    // The bridge secret and the bridge id (the handshake MAC key) are secret.
    mark_secret(&bridge);
    let bridge = black_box(&bridge);
    let accepted = ServerHandshake::accept(&mut r, bridge, &good, now);
    black_box(public(accepted.is_ok()));
    let rejected = ServerHandshake::accept(&mut r, bridge, &forged, now);
    black_box(public(rejected.is_ok()));
    drop(accepted);
}

// ----------------------------------------------------------------- pair_qr

fn pair_qr_transcript_ct_eq() {
    use ol_pair_qr::transcript::{TranscriptHash, TRANSCRIPT_LEN};
    let secret: [u8; TRANSCRIPT_LEN] = bytes(50);
    let mut near = secret;
    near[TRANSCRIPT_LEN - 1] ^= 1;
    let a = TranscriptHash::from_bytes(secret);
    mark_secret(&a);
    let a = black_box(&a);
    let same = a.ct_eq(&TranscriptHash::from_bytes(secret));
    let differ = a.ct_eq(&TranscriptHash::from_bytes(near));
    black_box(public((same, differ)));
}

fn pair_qr_chain_key() {
    use ol_pair_qr::transcript::{TranscriptHash, TRANSCRIPT_LEN};
    let t = TranscriptHash::from_bytes(bytes::<TRANSCRIPT_LEN>(53));
    let shared: [u8; 32] = bytes(54);
    let reference = ol_pair_qr::chain_key::derive_chain_key(&t, &shared);
    mark_secret(&shared);
    let derived = ol_pair_qr::chain_key::derive_chain_key(&t, black_box(&shared));
    let equal = derived == reference;
    black_box(public(equal));
}

// -------------------------------------------------------------- capability

fn capability_verify() {
    use ol_capability::{Capability, Caveat, Context, CAP_ID_LEN, ROOT_KEY_LEN};
    let root = zeroize::Zeroizing::new(bytes::<ROOT_KEY_LEN>(60));
    let id: [u8; CAP_ID_LEN] = bytes(61);
    let cap = Capability::root(id, &root)
        .attenuate(Caveat::ExpiresAt(1_000_000))
        .expect("caveat")
        .attenuate(Caveat::PathPrefix("/safe/folder".to_string()))
        .expect("caveat");
    let mut wire = cap.encode();
    let last = wire.len() - 1;
    wire[last] ^= 1;
    let forged = Capability::decode(&wire).expect("structurally valid");
    let ctx = Context::new()
        .with_now(500_000)
        .with_path("/safe/folder/x.txt");
    mark_secret(&*root);
    let root = black_box(&root);
    let good = cap.accepts(root, &ctx);
    let bad = forged.accepts(root, &ctx);
    black_box(public((good, bad)));
}

// ------------------------------------------------------------------ duress

fn duress_check(domain: &str, root: &[u8; 32], passphrase: &[u8]) -> [u8; 32] {
    let mut input = root.to_vec();
    input.extend_from_slice(passphrase);
    blake3::derive_key(domain, &input)
}

fn duress_open(which: u8) {
    let real_root: [u8; 32] = bytes(70);
    let duress_root: [u8; 32] = bytes(71);
    let pair_secret: [u8; 32] = bytes(72);
    let real_pw = *b"correct horse battery staple 01";
    let duress_pw = *b"coerced passphrase for decoy 02";
    let wrong_pw = *b"neither of the enrolled phrases";
    let real_check = duress_check("ol-duress-real-check-v1", &real_root, &real_pw);
    let duress_check_hash = duress_check("ol-duress-decoy-check-v1", &duress_root, &duress_pw);
    let gate = ol_duress::DuressGate::new(real_root, duress_root, pair_secret);
    let presented = match which {
        0 => real_pw,
        1 => duress_pw,
        _ => wrong_pw,
    };
    mark_secret(&gate);
    mark_secret(&presented);
    mark_secret(&real_check);
    mark_secret(&duress_check_hash);
    let outcome = black_box(&gate).open(black_box(&presented), &real_check, &duress_check_hash);
    // Which outcome occurred is the gate's public verdict.
    let kind: u8 = match &outcome {
        Ok(ol_duress::DuressOutcome::Real(_)) => 0,
        Ok(ol_duress::DuressOutcome::Duress { .. }) => 1,
        Err(_) => 2,
    };
    declassify(&kind);
    black_box(kind);
    drop(outcome);
}

fn duress_open_real() {
    duress_open(0);
}

fn duress_open_duress() {
    duress_open(1);
}

fn duress_open_rejected() {
    duress_open(2);
}

// ------------------------------------------------------------ confidential

fn confidential_unseal_tampered() {
    use ol_confidential::provider::ConfidentialProvider;
    use ol_confidential::software::SoftwareProvider;
    // The provider's AEAD key is secret; the sealed blob is public storage.
    let provider = SoftwareProvider::generate(&mut rng(90));
    let sealed = provider.seal_master(&bytes::<32>(91)).expect("seal");
    for position in [0usize, 13, 40, sealed.bytes.len() - 1] {
        let mut tampered = sealed.clone();
        tampered.bytes[position] ^= 0x80;
        mark_secret(&provider);
        let outcome = black_box(&provider).sealed_sign(&tampered, b"probe");
        black_box(public(outcome.is_ok()));
    }
}

// ------------------------------------------------------------------- pqkem

fn pqkem_decapsulate(malformed: bool) {
    let mut r = rng(80);
    let (pk, sk) = ol_pqkem::keypair(&mut r);
    let (ct, _) = ol_pqkem::encapsulate(&pk, &mut r).expect("encapsulate");
    let ct = if malformed {
        let mut wire = ct.to_bytes();
        wire[17] ^= 0xff;
        ol_pqkem::HybridCiphertext::from_bytes(&wire).expect("structurally valid")
    } else {
        ct
    };
    // FIPS 203 decapsulation key layout (ML-KEM-768, 2400 bytes):
    // s_hat (1152) || ek (1184: t_hat || rho) || H(ek) (32) || z (32), then
    // One Link appends the 32-byte X25519 scalar. ek and H(ek) are PUBLIC:
    // re-encryption rejection-samples the public matrix A from rho, which
    // may branch. Only s_hat, z and the X25519 scalar are marked secret.
    let mut wire = sk.to_bytes();
    mark_secret(&wire[..1152]);
    mark_secret(&wire[2368..2400]);
    mark_secret(&wire[2400..]);
    let sk = ol_pqkem::HybridSecretKey::from_bytes(black_box(&wire[..])).expect("round trip");
    wire.iter_mut().for_each(|b| *b = 0);
    let shared =
        ol_pqkem::decapsulate(black_box(&sk), &ct).expect("implicit rejection never errors");
    black_box(&shared);
}

fn pqkem_decapsulate_valid() {
    pqkem_decapsulate(false);
}

fn pqkem_decapsulate_malformed() {
    pqkem_decapsulate(true);
}

// ------------------------------------------------------------------- table

const CASES: &[Case] = &[
    Case {
        name: "control_branch_on_secret",
        expect: Expect::Flagged,
        covers: &[],
        what: "negative control: a branch on a secret bit around a call",
        run: control_branch_on_secret,
    },
    Case {
        name: "control_secret_table_index",
        expect: Expect::Flagged,
        covers: &[],
        what: "negative control: production gf_mul_fast, a secret-indexed 64 KiB table",
        run: control_secret_table_index,
    },
    Case {
        name: "control_short_circuit_zero_test",
        expect: Expect::Flagged,
        covers: &[],
        what: "negative control: iterator all() over a secret stops at its first non-zero byte",
        run: control_short_circuit_zero_test,
    },
    Case {
        name: "threshold_gf_mul",
        expect: Expect::Clean,
        covers: &["ol_threshold_recovery/tests/constant_time_gate.rs::gf_mul_constant_time_across_operand_buckets"],
        what: "GF(256) multiply of two secret operands",
        run: threshold_gf_mul,
    },
    Case {
        name: "threshold_gf_inv",
        expect: Expect::Clean,
        covers: &[],
        what: "GF(256) inverse of a secret operand",
        run: threshold_gf_inv,
    },
    Case {
        name: "threshold_share_byte",
        expect: Expect::Clean,
        covers: &[],
        what: "Shamir split of secret bytes with a secret coefficient stream",
        run: threshold_share_byte,
    },
    Case {
        name: "onion_hop_id_eq",
        expect: Expect::Clean,
        covers: &["ol_onion/tests/constant_time_gate.rs::hop_id_eq_constant_time"],
        what: "HopId equality with a secret operand",
        run: onion_hop_id_eq,
    },
    Case {
        name: "onion_layer_key_eq",
        expect: Expect::Clean,
        covers: &["ol_onion/tests/constant_time_gate.rs::layer_key_eq_constant_time"],
        what: "LayerKey equality with a secret operand",
        run: onion_layer_key_eq,
    },
    Case {
        name: "onion_header_mac_verify",
        expect: Expect::Clean,
        covers: &["ol_onion/tests/sphinx_ct_gate.rs::header_mac_verify_constant_time"],
        what: "Sphinx header MAC verification under a secret key, good and forged tags",
        run: onion_header_mac_verify,
    },
    Case {
        name: "onion_relay_layer_key",
        expect: Expect::Clean,
        covers: &[],
        what: "relay layer-key derivation and the small-order shared-secret test",
        run: onion_relay_layer_key,
    },
    Case {
        name: "sphinx_build",
        expect: Expect::Clean,
        covers: &[],
        what: "Sphinx packet construction under a secret sender ephemeral scalar",
        run: sphinx_build,
    },
    Case {
        name: "sphinx_final_hop_key",
        expect: Expect::Clean,
        covers: &[],
        what: "final-hop shared key derivation under a secret sender scalar",
        run: sphinx_final_hop_key,
    },
    Case {
        name: "sphinx_peel",
        expect: Expect::Clean,
        covers: &[],
        what: "relay-side Sphinx peel under a secret relay scalar",
        run: sphinx_peel,
    },
    Case {
        name: "obfs_server_accept",
        expect: Expect::Clean,
        covers: &["ol_onion/tests/constant_time_gate_obfs.rs::handshake_mac_verify_constant_time_across_tamper_positions"],
        what: "obfs bridge handshake accept under a secret bridge key and MAC key",
        run: obfs_server_accept,
    },
    Case {
        name: "pair_qr_transcript_ct_eq",
        expect: Expect::Clean,
        covers: &["ol_pair_qr/tests/constant_time_gate.rs::transcript_hash_ct_eq_constant_time"],
        what: "transcript hash comparison with a secret operand",
        run: pair_qr_transcript_ct_eq,
    },
    Case {
        name: "pair_qr_chain_key",
        expect: Expect::Clean,
        covers: &["ol_pair_qr/tests/constant_time_gate.rs::chain_key_eq_constant_time"],
        what: "chain-key derivation from a secret X25519 shared secret and its comparison",
        run: pair_qr_chain_key,
    },
    Case {
        name: "capability_verify",
        expect: Expect::Clean,
        covers: &["ol_capability/tests/constant_time.rs::signature_compare_timing_uniform"],
        what: "capability HMAC-chain verification under a secret root key, good and forged",
        run: capability_verify,
    },
    Case {
        name: "duress_open_real",
        expect: Expect::Clean,
        covers: &["ol_duress/tests/constant_time.rs::duress_open_timing_variance_under_120_percent_real_vs_duress"],
        what: "duress gate presented the real passphrase",
        run: duress_open_real,
    },
    Case {
        name: "duress_open_duress",
        expect: Expect::Clean,
        covers: &["ol_duress/tests/constant_time.rs::duress_open_timing_variance_under_120_percent_real_vs_duress"],
        what: "duress gate presented the duress passphrase",
        run: duress_open_duress,
    },
    Case {
        name: "duress_open_rejected",
        expect: Expect::Clean,
        covers: &["ol_duress/tests/constant_time.rs::duress_open_timing_variance_under_120_percent_real_vs_duress"],
        what: "duress gate presented an unenrolled passphrase",
        run: duress_open_rejected,
    },
    Case {
        name: "confidential_unseal_tampered",
        expect: Expect::Clean,
        covers: &["ol_confidential/tests/constant_time_gate.rs::ct_unseal_uniform_over_tamper_position"],
        what: "sealed-key unseal under the provider's secret AEAD key, tampered at several positions",
        run: confidential_unseal_tampered,
    },
    Case {
        name: "pqkem_decapsulate_valid",
        expect: Expect::Clean,
        covers: &["ol_pqkem/tests/constant_time.rs::adr0017_constant_time_decap_valid_vs_malformed"],
        what: "hybrid ML-KEM-768 + X25519 decapsulation of a valid ciphertext under a secret key",
        run: pqkem_decapsulate_valid,
    },
    Case {
        name: "pqkem_decapsulate_malformed",
        expect: Expect::Clean,
        covers: &["ol_pqkem/tests/constant_time.rs::adr0017_constant_time_decap_valid_vs_malformed"],
        what: "hybrid decapsulation of a tampered ciphertext (implicit rejection) under a secret key",
        run: pqkem_decapsulate_malformed,
    },
];

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

fn list() {
    for case in CASES {
        let covers: Vec<String> = case
            .covers
            .iter()
            .map(|c| format!("\"{}\"", json_escape(c)))
            .collect();
        let expect = match case.expect {
            Expect::Clean => "clean",
            Expect::Flagged => "flagged",
        };
        println!(
            "{{\"name\":\"{}\",\"expect\":\"{}\",\"covers\":[{}],\"what\":\"{}\"}}",
            json_escape(case.name),
            expect,
            covers.join(","),
            json_escape(case.what)
        );
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let native_smoke = args.iter().any(|a| a == "--native-smoke");
    let names: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    if args.iter().any(|a| a == "--list") {
        list();
        return ExitCode::SUCCESS;
    }
    let [name] = names.as_slice() else {
        eprintln!("usage: ol_ct_audit --list | ol_ct_audit <case> [--native-smoke]");
        return ExitCode::from(2);
    };
    let Some(case) = CASES.iter().find(|c| c.name == name.as_str()) else {
        eprintln!("unknown case {name}");
        return ExitCode::from(2);
    };
    let under_valgrind = running_on_valgrind();
    if !under_valgrind && !native_smoke {
        // Natively every client request is a no-op, so a "clean" run would
        // prove nothing. Refuse rather than report a vacuous pass.
        eprintln!(
            "ol_ct_audit: case {name} must run under Valgrind Memcheck (or pass --native-smoke)"
        );
        return ExitCode::from(3);
    }
    let before = error_count();
    (case.run)();
    let after = error_count();
    println!(
        "ct-audit-case-complete name={} valgrind={} errors={}",
        case.name,
        u8::from(under_valgrind),
        after.saturating_sub(before)
    );
    ExitCode::SUCCESS
}
