//! Constant-time timing regression gate for [`gf_mul`].
//!
//! Timing gates have two competing requirements: they must detect a stable
//! operand-dependent cost, and they must not confuse an unrelated scheduler
//! preemption with such a cost.  A single sequential pass cannot distinguish
//! those cases.  This gate therefore uses repeated, balanced Latin-square
//! scheduling and a robust median estimator:
//!
//! * every operand bucket is measured at every position in the schedule;
//! * each round is normalized by its median, removing common CPU-frequency
//!   drift without removing relative bucket cost;
//! * the median across rounds rejects isolated interrupts/preemptions; and
//! * the maximum pairwise median spread must remain below five percent.
//!
//! The measured call site is non-inlined and its operands cross
//! [`std::hint::black_box`] on every multiplication.  That prevents the
//! optimizer from specializing sixteen constant call sites or hoisting a pure
//! multiplication out of the loop.  The production implementation remains a
//! fixed eight-iteration, mask-and-XOR routine with no secret-dependent table
//! lookup or control-flow branch.  This test is a regression alarm for changes
//! that introduce an observable operand-dependent fast path; it is not a claim
//! that wall-clock sampling replaces a target-specific side-channel audit.

use std::{array, hint::black_box, time::Instant};

use ol_threshold_recovery::gf256::gf_mul;

const BUCKETS: usize = 16;
const MEASURED_ROUNDS: usize = 64;
const WARMUP_ROUNDS: usize = 4;
const SAMPLES_PER_MEASUREMENT: usize = 200_000;
const MAX_PAIRWISE_MEDIAN_SPREAD: f64 = 0.05;

const OPERAND_PAIRS: [(u32, u32); BUCKETS] = [
    (0x00, 0x00),
    (0x00, 0xFF),
    (0xFF, 0x00),
    (0xFF, 0xFF),
    (0x01, 0x80),
    (0x80, 0x01),
    (0x55, 0xAA),
    (0xAA, 0x55),
    (0x57, 0x83),
    (0x53, 0xCA),
    (0x10, 0x20),
    (0x42, 0x42),
    (0x7F, 0x80),
    (0xFE, 0x01),
    (0x33, 0xCC),
    (0x99, 0x66),
];

/// Keep a single dynamic call shape for every operand bucket.
///
/// `black_box` is intentionally inside the loop.  Applying it only to the
/// result would still permit loop-invariant code motion of the pure `gf_mul`.
#[inline(never)]
fn measure_ns(a: u32, b: u32, samples: usize) -> f64 {
    let mut accumulator = 0u32;
    let mut iteration_word = 0u32;
    let start = Instant::now();
    for _ in 0..samples {
        let product = gf_mul(black_box(a), black_box(b));
        accumulator = accumulator.wrapping_add(product ^ iteration_word);
        iteration_word = iteration_word.wrapping_add(1);
    }
    let elapsed = start.elapsed().as_secs_f64() * 1_000_000_000.0;
    black_box(accumulator);
    elapsed
}

fn median(values: &[f64]) -> f64 {
    assert!(!values.is_empty());
    let mut ordered = values.to_vec();
    ordered.sort_unstable_by(f64::total_cmp);
    let middle = ordered.len() / 2;
    if ordered.len().is_multiple_of(2) {
        ordered[middle - 1].midpoint(ordered[middle])
    } else {
        ordered[middle]
    }
}

/// Return a permutation whose rotations form a balanced Latin square.
///
/// Five is coprime to sixteen, so `position * 5` visits every bucket.  Across
/// each block of sixteen rotations, every bucket also occupies every timing
/// position exactly once.  Alternating direction between blocks additionally
/// cancels monotonic within-round drift.
fn bucket_at(round: usize, position: usize) -> usize {
    let rotation = round % BUCKETS;
    let permuted_position = (position * 5) % BUCKETS;
    if (round / BUCKETS).is_multiple_of(2) {
        (permuted_position + rotation) % BUCKETS
    } else {
        (rotation + BUCKETS - permuted_position) % BUCKETS
    }
}

fn representative_bucket_costs(samples: &[Vec<f64>; BUCKETS]) -> [f64; BUCKETS] {
    array::from_fn(|bucket| median(&samples[bucket]))
}

fn pairwise_spread(costs: &[f64; BUCKETS]) -> f64 {
    let minimum = costs.iter().copied().fold(f64::INFINITY, f64::min);
    let maximum = costs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    maximum / minimum - 1.0
}

#[test]
fn robust_estimator_rejects_a_stable_leak_but_not_isolated_preemption() {
    let mut flat: [Vec<f64>; BUCKETS] = array::from_fn(|_| vec![1.0; MEASURED_ROUNDS]);
    // One severe scheduler interruption per bucket must not look like a
    // repeatable operand-dependent effect.
    for (bucket, observations) in flat.iter_mut().enumerate() {
        observations[bucket] = 100.0;
    }
    assert!(pairwise_spread(&representative_bucket_costs(&flat)).abs() < f64::EPSILON);

    // A stable six-percent fast/slow path must remain visible even with the
    // same outliers.  This guards against accidentally making the estimator so
    // forgiving that it can no longer enforce the five-percent timing bound.
    let mut leaky = flat;
    for (index, observation) in leaky[BUCKETS - 1].iter_mut().enumerate() {
        if index != BUCKETS - 1 {
            *observation = 1.06;
        }
    }
    assert!(pairwise_spread(&representative_bucket_costs(&leaky)) > MAX_PAIRWISE_MEDIAN_SPREAD);
}

#[test]
fn gf_mul_constant_time_across_operand_buckets() {
    // Several complete balanced passes provide enough work to warm instruction
    // caches and let CPU frequency management settle before evidence is kept.
    for round in 0..WARMUP_ROUNDS {
        for position in 0..BUCKETS {
            let bucket = bucket_at(round, position);
            let (a, b) = OPERAND_PAIRS[bucket];
            black_box(measure_ns(a, b, SAMPLES_PER_MEASUREMENT / 4));
        }
    }

    let mut normalized_samples: [Vec<f64>; BUCKETS] =
        array::from_fn(|_| Vec::with_capacity(MEASURED_ROUNDS));

    for round in 0..MEASURED_ROUNDS {
        let mut raw_round = [0.0; BUCKETS];
        for position in 0..BUCKETS {
            let bucket = bucket_at(round, position);
            let (a, b) = OPERAND_PAIRS[bucket];
            raw_round[bucket] = measure_ns(a, b, SAMPLES_PER_MEASUREMENT);
        }

        let round_median = median(&raw_round);
        for bucket in 0..BUCKETS {
            normalized_samples[bucket].push(raw_round[bucket] / round_median);
        }
    }

    let costs = representative_bucket_costs(&normalized_samples);
    let spread = pairwise_spread(&costs);
    let fastest = costs
        .iter()
        .enumerate()
        .min_by(|(_, left), (_, right)| left.total_cmp(right))
        .map(|(index, _)| index)
        .expect("operand buckets are non-empty");
    let slowest = costs
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| left.total_cmp(right))
        .map(|(index, _)| index)
        .expect("operand buckets are non-empty");

    println!(
        "gf_mul robust timing: spread={:.2}% fastest={:?} ({:.5}) slowest={:?} ({:.5}) costs={costs:?}",
        spread * 100.0,
        OPERAND_PAIRS[fastest],
        costs[fastest],
        OPERAND_PAIRS[slowest],
        costs[slowest],
    );

    // This peak-to-peak bound is stricter than the old five-percent relative
    // standard-deviation bound: no pair of representative bucket costs may
    // differ by five percent, while isolated wall-clock outliers are ignored.
    assert!(
        spread < MAX_PAIRWISE_MEDIAN_SPREAD,
        "gf_mul representative operand-bucket costs differ by {:.2}% (limit {:.2}%): fastest {:?}, slowest {:?}",
        spread * 100.0,
        MAX_PAIRWISE_MEDIAN_SPREAD * 100.0,
        OPERAND_PAIRS[fastest],
        OPERAND_PAIRS[slowest],
    );
}
