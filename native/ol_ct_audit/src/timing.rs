//! Statistical timing-leak test of One Link's constant-time primitives.
//!
//! The Valgrind audit (`main.rs`) proves that no conditional branch and no
//! memory address in the release code depends on a secret. It cannot see an
//! instruction whose latency depends on its operands (integer division,
//! multiplication on some cores) or any other microarchitectural effect. This
//! module measures that residual with the dudect method (Reparaz, Balasch and
//! Verbauwhede, "Dude, is my code constant time?", DATE 2017):
//!
//! * Every target has two input classes. Class 0 holds the secret at one
//!   FIXED value; class 1 draws a fresh RANDOM secret for every call. Public
//!   inputs are identical in both classes, and both classes reach the same
//!   public verdict (both reject, both accept), so a difference can only come
//!   from the secret.
//! * The class of each measurement is an independent fair coin. Whatever else
//!   the machine does (other jobs, frequency changes, interrupts) is therefore
//!   independent of the class: it adds variance, which lowers power and is
//!   reported as such, but it cannot create a difference between the classes.
//!   That is what makes the test valid on a machine that is not quiet.
//! * All inputs of a batch are generated before any of them is timed, into
//!   one slot per call, so input preparation never runs inside a timed region
//!   and both classes read their input from the same slot positions. Outputs
//!   are parked and dropped after the batch, outside every timed region.
//! * One measurement is `calls` calls of the production function, each on its
//!   own input of the measurement's class, between two reads of the clock:
//!   `lfence; rdtsc; lfence` on x86-64, `Instant` elsewhere. `black_box` hides
//!   every input from the optimiser and forces every output to exist, and the
//!   function is called through a non-inlined shim.
//! * dudect's 100 percentile crops are fixed from a calibration sample (later
//!   discarded), and Welch's t-test runs on every crop and on the uncropped
//!   data with online (Welford) moments. A target LEAKS when |t| > 4.5 at any
//!   crop.
//!
//! A run that sees no leak is only as strong as its power, so every result
//! states its minimum detectable effect (MDE): the difference of class means
//! that would give |t| = 4.5 with the observed variances and sample sizes,
//! `4.5 * sqrt(var0 / n0 + var1 / n1)`. Cropping truncates a shifted
//! distribution, so a uniform shift `d` of every measurement moves a cropped
//! mean by only `s * d`, with `s = 1 - f(c) * (c - m(c)) / F(c)` for the crop
//! threshold `c`, density `f`, distribution function `F` and cropped mean `m`.
//! The headline MDE is the smallest `MDE / min(|s|, 1)` over the crops with
//! |s| >= 0.25, 1000 measurements per class and a spread of at least one
//! clock quantum (never more power than a crop's own unshifted MDE, and none
//! from an atom of identical readings), and `mde80` scales it by `(4.5 + z) / 4.5` with
//! `z = 0.8416` for 80 % power. A run with no leak whose `mde80` exceeds the
//! stated bound (a fraction of the run's median measurement net of the
//! clock's own overhead) is INCONCLUSIVE-POWER, not PASS.
//!
//! Negative controls leak by design (an early-exit byte compare; the
//! table-driven `gf_mul_fast`). The driver (`scripts/run_ct_timing.py`) fails
//! the run as blind when one is not detected. Null controls give both classes
//! the same input distribution but prepare class 1 through different, heavier
//! code; the driver fails the run as biased when one is flagged.
//!
//! Limits, stated so they are not mistaken for coverage: the test sees
//! differences in the mean of whole measurements after cropping, not every
//! difference of distribution; it measures this binary's code generation on
//! this host's microarchitecture; and each class design probes the secret
//! dependence it was built to probe (documented per target).

use std::fmt::Write as _;
use std::hint::black_box;
use std::ops::Range;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::json_escape;

// ================================================================ statistics

/// |t| above this at any crop is a leak (Reparaz et al., DATE 2017).
pub(crate) const T_THRESHOLD: f64 = 4.5;
/// |t| above this ends a run early: the difference is beyond doubt.
pub(crate) const DECISIVE_T: f64 = 10.0;
/// Standard-normal quantile for 80 % power: `Phi(Z_POWER_80) = 0.8`.
pub(crate) const Z_POWER_80: f64 = 0.841_621_233_572_914_3;
/// dudect's number of percentile crops.
pub(crate) const NUMBER_PERCENTILES: usize = 100;
/// A crop counts towards the headline power only with this many
/// measurements in each class.
pub(crate) const MIN_CLASS_N: u64 = 1_000;
/// ... and only when a shift moves its mean by at least this fraction.
pub(crate) const MIN_SENSITIVITY: f64 = 0.25;

/// The sensitivity a crop's MDE is divided by. |s| above 1 (a density spike
/// at the threshold, where a shift moves mass across it) is real but rests on
/// the local linear model, so no crop is credited with more power than its
/// own unshifted MDE: the claimed power is conservative.
pub(crate) fn effective_sensitivity(s: f64) -> f64 {
    s.abs().min(1.0)
}

/// Exact for every count this module produces (below 2^53).
#[allow(clippy::cast_precision_loss)]
fn to_f64(x: u64) -> f64 {
    x as f64
}

fn usize_to_f64(x: usize) -> f64 {
    to_f64(u64::try_from(x).unwrap_or(u64::MAX))
}

/// Online mean and second central moment (Welford), mergeable (Chan et al.).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Moments {
    pub(crate) n: u64,
    pub(crate) mean: f64,
    m2: f64,
}

impl Moments {
    pub(crate) fn push(&mut self, x: f64) {
        self.n += 1;
        let delta = x - self.mean;
        self.mean += delta / to_f64(self.n);
        self.m2 += delta * (x - self.mean);
    }

    /// The moments of the union of two samples.
    pub(crate) fn merge(self, other: Self) -> Self {
        if self.n == 0 {
            return other;
        }
        if other.n == 0 {
            return self;
        }
        let n = self.n + other.n;
        let (na, nb, nn) = (to_f64(self.n), to_f64(other.n), to_f64(n));
        let delta = other.mean - self.mean;
        Self {
            n,
            mean: self.mean + delta * nb / nn,
            m2: self.m2 + other.m2 + delta * delta * na * nb / nn,
        }
    }

    /// Unbiased sample variance (0 below two samples).
    pub(crate) fn variance(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            self.m2 / to_f64(self.n - 1)
        }
    }
}

/// Welch's standard error of the difference of two means.
pub(crate) fn welch_se(a: &Moments, b: &Moments) -> Option<f64> {
    if a.n < 2 || b.n < 2 {
        return None;
    }
    Some((a.variance() / to_f64(a.n) + b.variance() / to_f64(b.n)).sqrt())
}

/// Welch's t statistic, `(mean_b - mean_a) / se`; `None` when it is undefined.
pub(crate) fn welch_t(a: &Moments, b: &Moments) -> Option<f64> {
    let se = welch_se(a, b)?;
    (se > 0.0).then(|| (b.mean - a.mean) / se)
}

/// The difference of means that would give |t| = `threshold` with these
/// variances and sample sizes.
pub(crate) fn minimum_detectable_effect(a: &Moments, b: &Moments, threshold: f64) -> Option<f64> {
    welch_se(a, b).map(|se| threshold * se)
}

/// The same effect at 80 % power: a true shift of this size gives an
/// expected |t| of `threshold + z`, which exceeds `threshold` 80 % of the time.
pub(crate) fn mde_at_80_percent_power(mde: f64, threshold: f64) -> f64 {
    mde * (threshold + Z_POWER_80) / threshold
}

/// dudect's crop percentiles: `1 - 0.5^(10 (i + 1) / 100)` for i in 0..100.
pub(crate) fn dudect_percentiles() -> Vec<f64> {
    (1..=NUMBER_PERCENTILES)
        .map(|i| 1.0 - 0.5_f64.powf(10.0 * usize_to_f64(i) / usize_to_f64(NUMBER_PERCENTILES)))
        .collect()
}

/// dudect's percentile of a sorted sample: the element at `floor(len * which)`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) fn percentile(sorted: &[u64], which: f64) -> u64 {
    let position = (usize_to_f64(sorted.len()) * which) as usize;
    sorted[position.min(sorted.len() - 1)]
}

/// Measurements binned between the crop thresholds, one set of moments per
/// bin and class. Crop `j` (values strictly below `thresholds[j]`, as in
/// dudect) is the merge of bins `0..=j`; the uncropped sample merges all.
/// Exact, and O(log K) per measurement instead of O(K).
#[derive(Clone, Debug)]
pub(crate) struct CropAccumulator {
    thresholds: Vec<u64>,
    bins: [Vec<Moments>; 2],
    min: u64,
    max: u64,
}

impl CropAccumulator {
    pub(crate) fn new(thresholds: Vec<u64>) -> Self {
        debug_assert!(thresholds.windows(2).all(|w| w[0] <= w[1]));
        let bins = thresholds.len() + 1;
        Self {
            thresholds,
            bins: [
                vec![Moments::default(); bins],
                vec![Moments::default(); bins],
            ],
            min: u64::MAX,
            max: 0,
        }
    }

    pub(crate) fn push(&mut self, class: Class, x: u64) {
        let bin = self.thresholds.partition_point(|&t| t <= x);
        self.bins[class as usize][bin].push(to_f64(x));
        self.min = self.min.min(x);
        self.max = self.max.max(x);
    }

    pub(crate) fn total(&self, class: Class) -> u64 {
        self.bins[class as usize].iter().map(|m| m.n).sum()
    }

    /// Row 0 is uncropped; row `j + 1` is the crop below `thresholds[j]`.
    pub(crate) fn rows(&self, percentiles: &[f64]) -> Vec<CropRow> {
        let k = self.thresholds.len();
        let mut prefix = [Moments::default(); 2];
        let mut cropped = Vec::with_capacity(k);
        for j in 0..k {
            for (class, acc) in prefix.iter_mut().enumerate() {
                *acc = acc.merge(self.bins[class][j]);
            }
            cropped.push(prefix);
        }
        let total = [
            prefix[0].merge(self.bins[0][k]),
            prefix[1].merge(self.bins[1][k]),
        ];
        let mut rows = Vec::with_capacity(k + 1);
        rows.push(CropRow::new(None, None, total, 1.0));
        for (j, moments) in cropped.into_iter().enumerate() {
            let sensitivity = self.shift_sensitivity(j, &moments);
            rows.push(CropRow::new(
                percentiles.get(j).copied(),
                Some(self.thresholds[j]),
                moments,
                sensitivity,
            ));
        }
        rows
    }

    fn pooled_count(&self, bin: usize) -> u64 {
        self.bins[0][bin].n + self.bins[1][bin].n
    }

    /// `s = 1 - f(c) (c - m(c)) / F(c)` for the crop below `c =
    /// thresholds[j]`: the rate at which a uniform shift of every
    /// measurement moves this crop's mean. `f` is the pooled histogram
    /// density between the nearest distinct thresholds around `c` (the
    /// observed extremes at the ends).
    fn shift_sensitivity(&self, j: usize, crop: &[Moments; 2]) -> f64 {
        let k = self.thresholds.len();
        let total: u64 = (0..=k).map(|b| self.pooled_count(b)).sum();
        let pooled = crop[0].merge(crop[1]);
        if total == 0 || pooled.n == 0 {
            return 0.0;
        }
        let c = self.thresholds[j];
        let lower_edge = |b: usize| {
            if b == 0 {
                self.min
            } else {
                self.thresholds[b - 1]
            }
        };
        let upper_edge = |b: usize| {
            if b == k {
                self.max.saturating_add(1)
            } else {
                self.thresholds[b]
            }
        };
        let left = self.thresholds[..j]
            .iter()
            .rev()
            .copied()
            .find(|&t| t < c)
            .unwrap_or_else(|| self.min.min(c));
        let right = self.thresholds[j + 1..]
            .iter()
            .copied()
            .find(|&t| t > c)
            .unwrap_or_else(|| self.max.saturating_add(1).max(c));
        if right <= left {
            return 0.0;
        }
        let mass: u64 = (0..=k)
            .filter(|&b| lower_edge(b) >= left && upper_edge(b) <= right)
            .map(|b| self.pooled_count(b))
            .sum();
        let density = to_f64(mass) / (to_f64(total) * to_f64(right - left));
        let fraction = to_f64(pooled.n) / to_f64(total);
        1.0 - density * (to_f64(c) - pooled.mean) / fraction
    }

    pub(crate) fn histogram(&self, class: Class) -> Vec<u64> {
        self.bins[class as usize].iter().map(|m| m.n).collect()
    }
}

/// One crop's test: moments per class, t, MDE and the shift sensitivity.
#[derive(Clone, Debug)]
pub(crate) struct CropRow {
    pub(crate) percentile: Option<f64>,
    pub(crate) threshold: Option<u64>,
    pub(crate) fixed: Moments,
    pub(crate) random: Moments,
    pub(crate) t: Option<f64>,
    pub(crate) mde: Option<f64>,
    pub(crate) sensitivity: f64,
    pub(crate) mde_shift: Option<f64>,
}

impl CropRow {
    fn new(
        percentile: Option<f64>,
        threshold: Option<u64>,
        moments: [Moments; 2],
        sensitivity: f64,
    ) -> Self {
        let [fixed, random] = moments;
        let mde = minimum_detectable_effect(&fixed, &random, T_THRESHOLD);
        let effective = effective_sensitivity(sensitivity);
        let mde_shift = mde.and_then(|m| (effective > 0.0).then(|| m / effective));
        Self {
            percentile,
            threshold,
            fixed,
            random,
            t: welch_t(&fixed, &random),
            mde,
            sensitivity,
            mde_shift,
        }
    }

    /// A crop backs a power claim only with enough measurements, a
    /// sensitivity a shift can move, and a spread of at least one clock
    /// quantum: below that the readings are an atom whose mean a sub-quantum
    /// shift cannot move linearly (no dithering), so its variance says
    /// nothing about power.
    fn usable_for_power(&self, quantum: f64) -> bool {
        self.fixed.n >= MIN_CLASS_N
            && self.random.n >= MIN_CLASS_N
            && self.sensitivity.abs() >= MIN_SENSITIVITY
            && self.fixed.merge(self.random).variance().sqrt() >= quantum
    }
}

fn gcd(a: u64, b: u64) -> u64 {
    let (mut a, mut b) = (a, b);
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// The clock's reading quantum: the greatest common divisor of the run's
/// thinned readings (2 when, as on some hosts, every delta is even).
pub(crate) fn reading_quantum<'a>(values: impl IntoIterator<Item = &'a u64>) -> u64 {
    values.into_iter().copied().fold(0, gcd).max(1)
}

/// The most sensitive crop for a uniform shift, and its MDE.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Headline {
    pub(crate) row: usize,
    pub(crate) mde: f64,
    pub(crate) mde80: f64,
}

pub(crate) fn headline(rows: &[CropRow], quantum: u64) -> Option<Headline> {
    let quantum = to_f64(quantum);
    rows.iter()
        .enumerate()
        .filter(|(_, r)| r.usable_for_power(quantum))
        .filter_map(|(i, r)| r.mde_shift.map(|m| (i, m)))
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(row, mde)| Headline {
            row,
            mde,
            mde80: mde_at_80_percent_power(mde, T_THRESHOLD),
        })
}

pub(crate) fn max_abs_t(rows: &[CropRow]) -> Option<(usize, f64)> {
    rows.iter()
        .enumerate()
        .filter_map(|(i, r)| r.t.map(|t| (i, t.abs())))
        .max_by(|a, b| a.1.total_cmp(&b.1))
}

pub(crate) const VERDICT_PASS: &str = "PASS";
pub(crate) const VERDICT_LEAK: &str = "LEAK";
pub(crate) const VERDICT_INCONCLUSIVE: &str = "INCONCLUSIVE-POWER";

/// LEAK at |t| > 4.5 on any crop; otherwise PASS only when a shift of
/// `bound` (as a fraction of the net median) would have been detected
/// with 80 % power.
pub(crate) fn verdict(
    max_abs_t: Option<f64>,
    mde80_fraction: Option<f64>,
    bound: f64,
) -> &'static str {
    if max_abs_t.is_some_and(|t| t > T_THRESHOLD) {
        VERDICT_LEAK
    } else if mde80_fraction.is_some_and(|f| f <= bound) {
        VERDICT_PASS
    } else {
        VERDICT_INCONCLUSIVE
    }
}

// ===================================================================== clock

#[cfg(target_arch = "x86_64")]
mod clock {
    use core::arch::x86_64::{_mm_lfence, _rdtsc};

    pub(crate) const NAME: &str = "rdtsc between lfence barriers";
    pub(crate) const UNIT: &str = "tsc_ticks";

    /// The time-stamp counter, serialised so that neither earlier nor later
    /// instructions execute across the read.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub(crate) fn now() -> u64 {
        // SAFETY: `lfence` (SSE2) and `rdtsc` are baseline x86-64
        // instructions with no memory operands and no preconditions.
        unsafe {
            _mm_lfence();
            let ticks = _rdtsc();
            _mm_lfence();
            ticks
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod clock {
    use std::sync::OnceLock;
    use std::time::Instant;

    pub(crate) const NAME: &str = "std::time::Instant";
    pub(crate) const UNIT: &str = "ns";

    static BASE: OnceLock<Instant> = OnceLock::new();

    #[inline]
    pub(crate) fn now() -> u64 {
        let elapsed = BASE.get_or_init(Instant::now).elapsed();
        u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Median cost of the clock itself (two back-to-back reads).
fn clock_overhead() -> u64 {
    let mut samples: Vec<u64> = (0..20_000)
        .map(|_| {
            let start = clock::now();
            let end = clock::now();
            end.wrapping_sub(start)
        })
        .collect();
    samples.sort_unstable();
    percentile(&samples, 0.5)
}

// ==================================================================== engine

/// Measurement class. Class 0 is the fixed secret, class 1 the random one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Fixed = 0,
    Random = 1,
}

fn coin(rng: &mut ChaCha20Rng) -> Class {
    if rng.next_u32() & 1 == 0 {
        Class::Fixed
    } else {
        Class::Random
    }
}

/// One target: how to build its public context, how to draw an input of
/// each class, and the measured call.
trait Harness: Sized {
    type Input;
    type Output;
    fn setup(rng: &mut ChaCha20Rng) -> Self;
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> Self::Input;
    /// The measured call. Implementations are `#[inline(never)]` so the
    /// production function is compiled as for an ordinary caller, not fused
    /// with the timing loop.
    fn run(&mut self, input: &Self::Input) -> Self::Output;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expect {
    /// Production code claimed constant-time: must not leak.
    ConstantTime,
    /// Negative control: must be detected.
    Leak,
    /// Null control: both classes have the same input distribution, so a
    /// flag is a false positive of the harness or the statistics.
    Null,
}

/// Run parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Config {
    pub(crate) budget: Duration,
    pub(crate) min_time: Duration,
    pub(crate) min_measurements: u64,
    pub(crate) mde_goal: f64,
    pub(crate) mde_bound: f64,
    pub(crate) seed: u64,
}

const WARMUP_MEASUREMENTS: usize = 2_000;
const CALIBRATION_MEASUREMENTS: usize = 20_000;
/// dudect discards the first measurements of every batch.
const DISCARD_PER_BATCH: usize = 10;
/// Inputs plus parked outputs of one batch stay within this many bytes, so
/// a batch's slots stay cache-resident for both classes alike.
const BATCH_BYTES: usize = 256 * 1024;
const MIN_BATCH: usize = 64;
const MAX_BATCH: usize = 4_096;
/// A wrapped or absurd reading (counter moved backwards).
const ANOMALY: u64 = 1 << 62;
const SUMMARY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopReason {
    PowerGoal,
    DecisiveLeak,
    Budget,
}

impl StopReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::PowerGoal => "power_goal",
            Self::DecisiveLeak => "decisive_leak",
            Self::Budget => "budget",
        }
    }
}

/// Capacity of each class's thinned sample.
const THINNED_CAPACITY: usize = 1 << 15;
/// Quantiles reported per class from the thinned samples.
const REPORTED_QUANTILES: [f64; 7] = [0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99];

/// Every `stride`-th measurement of one class, the stride doubling whenever
/// the sample fills: a deterministic subsample spread evenly over the whole
/// run, so the run's quantiles are not the calibration window's (this host's
/// state drifts within a run: frequency, core type, load).
#[derive(Clone, Debug)]
pub(crate) struct Thinned {
    stride: u64,
    seen: u64,
    values: Vec<u64>,
}

impl Thinned {
    pub(crate) fn new() -> Self {
        Self {
            stride: 1,
            seen: 0,
            values: Vec::with_capacity(THINNED_CAPACITY),
        }
    }

    pub(crate) fn push(&mut self, x: u64) {
        if self.seen.is_multiple_of(self.stride) {
            self.values.push(x);
            if self.values.len() >= THINNED_CAPACITY {
                let mut index = 0usize;
                self.values.retain(|_| {
                    index += 1;
                    index % 2 == 1
                });
                self.stride *= 2;
            }
        }
        self.seen += 1;
    }

    pub(crate) fn sorted(&self) -> Vec<u64> {
        let mut sorted = self.values.clone();
        sorted.sort_unstable();
        sorted
    }
}

/// The run's median measurement net of the clock's overhead: the smaller
/// class median, so the fraction it scales is the conservative one.
fn net_median(thinned: &[Thinned; 2], clock_overhead: u64) -> u64 {
    thinned
        .iter()
        .filter(|t| !t.values.is_empty())
        .map(|t| percentile(&t.sorted(), 0.5))
        .min()
        .unwrap_or(0)
        .saturating_sub(clock_overhead)
        .max(1)
}

/// Everything one target run produced.
#[derive(Debug)]
pub(crate) struct Outcome {
    batch: usize,
    clock_overhead: u64,
    calibration_median: u64,
    warmup: usize,
    calibration: usize,
    anomalies: u64,
    elapsed: Duration,
    ticks_per_second: f64,
    stop: StopReason,
    percentiles: Vec<f64>,
    acc: CropAccumulator,
    thinned: [Thinned; 2],
}

struct Engine<H: Harness> {
    harness: H,
    rng: ChaCha20Rng,
    calls: usize,
    batch: usize,
    inputs: Vec<H::Input>,
    outputs: Vec<Option<H::Output>>,
    classes: Vec<Class>,
    times: Vec<u64>,
}

impl<H: Harness> Engine<H> {
    fn new(harness: H, rng: ChaCha20Rng, calls: usize) -> Self {
        let per_call = std::mem::size_of::<H::Input>() + std::mem::size_of::<Option<H::Output>>();
        let batch = (BATCH_BYTES / (calls * per_call.max(1))).clamp(MIN_BATCH, MAX_BATCH);
        Self {
            harness,
            rng,
            calls,
            batch,
            inputs: Vec::with_capacity(batch * calls),
            outputs: (0..batch * calls).map(|_| None).collect(),
            classes: vec![Class::Fixed; batch],
            times: vec![0; batch],
        }
    }

    /// Prepare every input of a batch, then time each measurement, then
    /// drop the outputs and inputs. Nothing class-dependent runs between the
    /// two clock reads of a measurement.
    fn run_batch(&mut self) {
        self.inputs.clear();
        for slot in &mut self.classes {
            let class = coin(&mut self.rng);
            *slot = class;
            for _ in 0..self.calls {
                let input = self.harness.input(class, &mut self.rng);
                self.inputs.push(input);
            }
        }
        let calls = self.calls;
        for (j, time) in self.times.iter_mut().enumerate() {
            let inputs = &self.inputs[j * calls..(j + 1) * calls];
            let outputs = &mut self.outputs[j * calls..(j + 1) * calls];
            let start = clock::now();
            for (input, output) in inputs.iter().zip(outputs.iter_mut()) {
                *output = Some(black_box(self.harness.run(black_box(input))));
            }
            let end = clock::now();
            *time = end.wrapping_sub(start);
        }
        for output in &mut self.outputs {
            *output = None;
        }
        self.inputs.clear();
    }

    /// The measurements of the last batch that count (dudect discards the
    /// first few of every batch).
    fn kept(&self) -> impl Iterator<Item = (Class, u64)> + '_ {
        let skip = DISCARD_PER_BATCH.min(self.batch / 4);
        self.classes
            .iter()
            .copied()
            .zip(self.times.iter().copied())
            .skip(skip)
    }

    fn execute(mut self, target: &Target, cfg: &Config) -> Outcome {
        let clock_overhead = clock_overhead();
        let started = Instant::now();
        let ticks_at_start = clock::now();

        let mut warmup = 0;
        while warmup < WARMUP_MEASUREMENTS {
            self.run_batch();
            warmup += self.batch;
        }

        let mut sample = Vec::with_capacity(CALIBRATION_MEASUREMENTS + self.batch);
        while sample.len() < CALIBRATION_MEASUREMENTS {
            self.run_batch();
            sample.extend(self.kept().map(|(_, t)| t).filter(|&t| t < ANOMALY));
        }
        sample.sort_unstable();
        let percentiles = dudect_percentiles();
        let thresholds: Vec<u64> = percentiles
            .iter()
            .map(|&p| percentile(&sample, p))
            .collect();
        let calibration_median = percentile(&sample, 0.5);
        let calibration = sample.len();
        drop(sample);

        let mut acc = CropAccumulator::new(thresholds);
        let mut thinned = [Thinned::new(), Thinned::new()];
        let mut anomalies = 0u64;
        let mut last_summary = Instant::now();
        let stop = loop {
            self.run_batch();
            for (class, time) in self.kept() {
                if time >= ANOMALY {
                    anomalies += 1;
                } else {
                    acc.push(class, time);
                    thinned[class as usize].push(time);
                }
            }
            let elapsed = started.elapsed();
            if elapsed >= cfg.budget {
                break StopReason::Budget;
            }
            let measured = acc.total(Class::Fixed) + acc.total(Class::Random);
            if elapsed < cfg.min_time
                || measured < cfg.min_measurements
                || last_summary.elapsed() < SUMMARY_INTERVAL
            {
                continue;
            }
            last_summary = Instant::now();
            let rows = acc.rows(&percentiles);
            if max_abs_t(&rows).is_some_and(|(_, t)| t > DECISIVE_T) {
                break StopReason::DecisiveLeak;
            }
            if target.expect != Expect::Leak {
                let net = to_f64(net_median(&thinned, clock_overhead));
                let quantum = reading_quantum(thinned.iter().flat_map(|t| &t.values));
                if headline(&rows, quantum).is_some_and(|h| h.mde80 / net <= cfg.mde_goal) {
                    break StopReason::PowerGoal;
                }
            }
        };
        let elapsed = started.elapsed();
        let ticks = clock::now().wrapping_sub(ticks_at_start);
        Outcome {
            batch: self.batch,
            clock_overhead,
            calibration_median,
            warmup,
            calibration,
            anomalies,
            elapsed,
            ticks_per_second: to_f64(ticks) / elapsed.as_secs_f64(),
            stop,
            percentiles,
            acc,
            thinned,
        }
    }
}

fn measure<H: Harness>(target: &Target, cfg: &Config) -> Outcome {
    let mut rng = ChaCha20Rng::seed_from_u64(cfg.seed ^ name_hash(target.name));
    let harness = H::setup(&mut rng);
    Engine::new(harness, rng, target.calls).execute(target, cfg)
}

fn name_hash(name: &str) -> u64 {
    // FNV-1a: a per-target stream so targets never share random inputs.
    name.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

// ================================================================== helpers

fn bytes<const N: usize>(rng: &mut ChaCha20Rng) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}

/// `value` with its last byte changed: a probe that agrees with the secret
/// on every byte but the last, so an early-exit compare would scan it all.
fn near<const N: usize>(value: [u8; N]) -> [u8; N] {
    let mut out = value;
    out[N - 1] ^= 1;
    out
}

fn pick<'a, T>(pool: &'a [T], rng: &mut ChaCha20Rng) -> &'a T {
    let index = usize::try_from(rng.next_u32()).unwrap_or(0) % pool.len();
    &pool[index]
}

// ================================================================= controls

/// A byte-at-a-time compare that returns at the first difference.
/// `black_box` on every byte keeps the compiler from vectorising it.
fn early_exit_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for (x, y) in a.iter().zip(b) {
        if black_box(*x) != *y {
            return false;
        }
    }
    true
}

struct ControlEarlyExit {
    secret: [u8; 32],
    probe: [u8; 32],
}

impl Harness for ControlEarlyExit {
    type Input = [u8; 32];
    type Output = bool;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        let secret = bytes(rng);
        let probe = near(secret);
        assert!(
            !early_exit_eq(&secret, &probe),
            "control classes must both mismatch"
        );
        Self { secret, probe }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> [u8; 32] {
        match class {
            Class::Fixed => self.secret,
            Class::Random => bytes(rng),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &[u8; 32]) -> bool {
        early_exit_eq(input, &self.probe)
    }
}

struct ControlTableLookup;

impl Harness for ControlTableLookup {
    type Input = [u8; 2];
    type Output = u8;
    fn setup(_rng: &mut ChaCha20Rng) -> Self {
        // Build the 64 KiB table before anything is timed.
        black_box(ol_threshold_recovery::gf_mul_fast(
            black_box(3),
            black_box(7),
        ));
        Self
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> [u8; 2] {
        match class {
            Class::Fixed => [0, 0],
            Class::Random => bytes(rng),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &[u8; 2]) -> u8 {
        ol_threshold_recovery::gf_mul_fast(input[0], input[1])
    }
}

/// Bytes of scratch memory one class-1 input of the preparation null control
/// writes, at a random offset in a 256 KiB buffer.
const NULL_PREP_SWEEP: usize = 1_024;

/// Null control for the harness itself: uniform operands for `gf_mul` in
/// both classes, but class 1's are produced through a different and much
/// heavier path (a BLAKE3 hash of fresh randomness, then a 1 KiB write
/// sweep at a random offset of a 256 KiB buffer). If class-dependent
/// preparation reached the timed region, this would be flagged.
struct ControlNullPrep {
    scratch: Vec<u8>,
}

impl Harness for ControlNullPrep {
    type Input = [u8; 2];
    type Output = u32;
    fn setup(_rng: &mut ChaCha20Rng) -> Self {
        Self {
            scratch: vec![0u8; 256 * 1024],
        }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> [u8; 2] {
        match class {
            Class::Fixed => bytes(rng),
            Class::Random => {
                let digest = blake3::hash(&bytes::<32>(rng));
                let hashed = digest.as_bytes();
                let span = self.scratch.len() - NULL_PREP_SWEEP;
                let offset = usize::from(u16::from_le_bytes([hashed[2], hashed[3]])) * 4 % span;
                for (i, byte) in self.scratch[offset..offset + NULL_PREP_SWEEP]
                    .iter_mut()
                    .enumerate()
                {
                    *byte = byte.wrapping_add(hashed[i % 32]);
                }
                black_box(&mut self.scratch);
                [hashed[0], hashed[1]]
            }
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &[u8; 2]) -> u32 {
        ol_threshold_recovery::gf_mul(u32::from(input[0]), u32::from(input[1]))
    }
}

// ======================================================= threshold recovery

struct GfMul;

impl Harness for GfMul {
    type Input = [u8; 2];
    type Output = u32;
    fn setup(_rng: &mut ChaCha20Rng) -> Self {
        Self
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> [u8; 2] {
        match class {
            Class::Fixed => [0, 0],
            Class::Random => bytes(rng),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &[u8; 2]) -> u32 {
        ol_threshold_recovery::gf_mul(u32::from(input[0]), u32::from(input[1]))
    }
}

struct GfInv;

impl Harness for GfInv {
    type Input = u8;
    type Output = u32;
    fn setup(_rng: &mut ChaCha20Rng) -> Self {
        Self
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> u8 {
        match class {
            Class::Fixed => 0,
            Class::Random => bytes::<1>(rng)[0],
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &u8) -> u32 {
        ol_threshold_recovery::gf_inv(u32::from(*input))
    }
}

struct ShareByte {
    state: ol_threshold_recovery::PrngState,
}

impl Harness for ShareByte {
    type Input = (u8, ol_threshold_recovery::PrngState);
    type Output = Result<Vec<ol_threshold_recovery::Share>, ol_threshold_recovery::ShareError>;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        Self {
            state: ol_threshold_recovery::PrngState::new(rng.next_u64()),
        }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> Self::Input {
        match class {
            Class::Fixed => (0, self.state),
            Class::Random => (
                bytes::<1>(rng)[0],
                ol_threshold_recovery::PrngState::new(rng.next_u64()),
            ),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &Self::Input) -> Self::Output {
        let mut state = input.1;
        ol_threshold_recovery::share_byte(input.0, 3, 5, &mut state)
    }
}

// ===================================================================== quic

/// The dialer's server-certificate check (`IdentityBoundServerVerifier`):
/// the fingerprint the dialer expects is the secret, the presented
/// certificate is public, and both classes reject it. The server name and
/// the time are fixed outside the timed call.
struct QuicServerCertFingerprint {
    cert: rustls::pki_types::CertificateDer<'static>,
    name: rustls::pki_types::ServerName<'static>,
    now: rustls::pki_types::UnixTime,
    near_expected: ol_quic::PeerFingerprint,
}

impl QuicServerCertFingerprint {
    fn accepts(&self, verifier: &ol_quic::IdentityBoundServerVerifier) -> bool {
        use rustls::client::danger::ServerCertVerifier;
        verifier
            .verify_server_cert(&self.cert, &[], &self.name, &[], self.now)
            .is_ok()
    }
}

impl Harness for QuicServerCertFingerprint {
    type Input = ol_quic::IdentityBoundServerVerifier;
    type Output = bool;
    fn setup(_rng: &mut ChaCha20Rng) -> Self {
        let identity = ol_quic::Identity::generate().expect("a fresh QUIC identity");
        let harness = Self {
            cert: identity.cert_der().into_owned(),
            name: rustls::pki_types::ServerName::try_from("peer.invalid")
                .expect("a valid DNS name"),
            // Read once in setup, never inside the timed call.
            now: rustls::pki_types::UnixTime::now(),
            near_expected: near(identity.fingerprint()),
        };
        assert!(
            harness.accepts(&ol_quic::IdentityBoundServerVerifier::new(
                identity.fingerprint()
            )),
            "the matching fingerprint must verify"
        );
        assert!(
            !harness.accepts(&ol_quic::IdentityBoundServerVerifier::new(
                harness.near_expected
            )),
            "both classes must reject"
        );
        harness
    }
    fn input(
        &mut self,
        class: Class,
        rng: &mut ChaCha20Rng,
    ) -> ol_quic::IdentityBoundServerVerifier {
        ol_quic::IdentityBoundServerVerifier::new(match class {
            Class::Fixed => self.near_expected,
            Class::Random => bytes(rng),
        })
    }
    #[inline(never)]
    fn run(&mut self, input: &ol_quic::IdentityBoundServerVerifier) -> bool {
        self.accepts(input)
    }
}

// ==================================================================== onion

struct HopIdEq {
    secret: ol_onion::HopId,
    probe: ol_onion::HopId,
}

impl Harness for HopIdEq {
    type Input = ol_onion::HopId;
    type Output = bool;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        let secret: [u8; ol_onion::HOP_ID_LEN] = bytes(rng);
        Self {
            secret: ol_onion::HopId::from_bytes(secret),
            probe: ol_onion::HopId::from_bytes(near(secret)),
        }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> ol_onion::HopId {
        match class {
            Class::Fixed => self.secret,
            Class::Random => ol_onion::HopId::from_bytes(bytes(rng)),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &ol_onion::HopId) -> bool {
        *input == self.probe
    }
}

struct LayerKeyEq {
    secret: [u8; 32],
    probe: ol_onion::keyderiv::LayerKey,
}

impl Harness for LayerKeyEq {
    type Input = ol_onion::keyderiv::LayerKey;
    type Output = bool;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        let secret = bytes(rng);
        Self {
            secret,
            probe: ol_onion::keyderiv::LayerKey::from_bytes(near(secret)),
        }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> Self::Input {
        match class {
            Class::Fixed => ol_onion::keyderiv::LayerKey::from_bytes(self.secret),
            Class::Random => ol_onion::keyderiv::LayerKey::from_bytes(bytes(rng)),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &Self::Input) -> bool {
        *input == self.probe
    }
}

struct HeaderMacVerify {
    key: [u8; 32],
    header: Vec<u8>,
    tag: [u8; ol_onion::sphinx::primitives::SLOT_MAC_LEN],
}

impl Harness for HeaderMacVerify {
    type Input = [u8; 32];
    type Output = bool;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        use ol_onion::sphinx::primitives::{header_mac, verify_header_mac, HEADER_LEN};
        let key = bytes(rng);
        let mut header = vec![0u8; HEADER_LEN];
        rng.fill_bytes(&mut header);
        let good = header_mac(&key, &header);
        assert!(verify_header_mac(&key, &header, &good), "MAC must verify");
        let tag = near(good);
        assert!(
            !verify_header_mac(&key, &header, &tag),
            "near-miss tag must be rejected"
        );
        Self { key, header, tag }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> [u8; 32] {
        match class {
            Class::Fixed => self.key,
            Class::Random => bytes(rng),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &[u8; 32]) -> bool {
        ol_onion::sphinx::primitives::verify_header_mac(input, &self.header, &self.tag)
    }
}

const OBFS_NOW: u64 = 1_700_000_000;
const BRIDGE_POOL: usize = 1_024;

/// `VALID = false`: a prober's forged first message (the fixed bridge's
/// valid message with its last tag byte flipped), so both classes are
/// rejected at the MAC. `VALID = true`: a genuine first message, accepted by
/// every bridge that shares the fixed bridge id; only the static X25519
/// secret varies, and both classes run the ECDH and the session derivation.
struct ObfsAccept<const VALID: bool> {
    fixed: ol_onion::transport_obfs::BridgeKeypair,
    pool: Vec<ol_onion::transport_obfs::BridgeKeypair>,
    message: [u8; ol_onion::transport_obfs::HANDSHAKE_LEN],
    rng: ChaCha20Rng,
}

impl<const VALID: bool> Harness for ObfsAccept<VALID> {
    type Input = ol_onion::transport_obfs::BridgeKeypair;
    type Output = ol_onion::transport_obfs::HandshakeResult<(
        [u8; ol_onion::transport_obfs::HANDSHAKE_LEN],
        ol_onion::transport_obfs::Session,
    )>;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        use ol_onion::transport_obfs::{
            BridgeKeypair, ClientHandshake, ServerHandshake, HANDSHAKE_LEN,
        };
        let fixed = BridgeKeypair::from_parts(bytes(rng), bytes(rng));
        let client =
            ClientHandshake::start(rng, &fixed.public_bytes(), &fixed.id_bytes(), OBFS_NOW);
        let mut message = *client.first_message();
        if !VALID {
            message[HANDSHAKE_LEN - 1] ^= 1;
        }
        let pool: Vec<BridgeKeypair> = (0..BRIDGE_POOL)
            .map(|_| {
                let id = if VALID { fixed.id_bytes() } else { bytes(rng) };
                BridgeKeypair::from_parts(bytes(rng), id)
            })
            .collect();
        let mut server_rng = ChaCha20Rng::seed_from_u64(rng.next_u64());
        for bridge in [&fixed, &pool[0]] {
            let accepted = ServerHandshake::accept(&mut server_rng, bridge, &message, OBFS_NOW);
            assert_eq!(
                accepted.is_ok(),
                VALID,
                "both classes must reach the same verdict"
            );
        }
        Self {
            fixed,
            pool,
            message,
            rng: server_rng,
        }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> Self::Input {
        match class {
            Class::Fixed => self.fixed.clone(),
            Class::Random => pick(&self.pool, rng).clone(),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &Self::Input) -> Self::Output {
        ol_onion::transport_obfs::ServerHandshake::accept(
            &mut self.rng,
            input,
            &self.message,
            OBFS_NOW,
        )
    }
}

// ================================================================== pair_qr

struct TranscriptCtEq {
    secret: ol_pair_qr::transcript::TranscriptHash,
    probe: ol_pair_qr::transcript::TranscriptHash,
}

impl Harness for TranscriptCtEq {
    type Input = ol_pair_qr::transcript::TranscriptHash;
    type Output = bool;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        use ol_pair_qr::transcript::{TranscriptHash, TRANSCRIPT_LEN};
        let secret: [u8; TRANSCRIPT_LEN] = bytes(rng);
        Self {
            secret: TranscriptHash::from_bytes(secret),
            probe: TranscriptHash::from_bytes(near(secret)),
        }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> Self::Input {
        match class {
            Class::Fixed => self.secret,
            Class::Random => ol_pair_qr::transcript::TranscriptHash::from_bytes(bytes(rng)),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &Self::Input) -> bool {
        input.ct_eq(&self.probe)
    }
}

struct ChainKeyEq {
    transcript: ol_pair_qr::transcript::TranscriptHash,
    shared: [u8; 32],
    reference: ol_pair_qr::chain_key::ChainKey,
}

impl Harness for ChainKeyEq {
    type Input = [u8; 32];
    type Output = bool;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        use ol_pair_qr::chain_key::{derive_chain_key, ChainKey};
        let transcript = ol_pair_qr::transcript::TranscriptHash::from_bytes(bytes(rng));
        let shared = bytes(rng);
        let derived = derive_chain_key(&transcript, &shared);
        let reference = ChainKey::from_bytes(near(*derived.as_bytes()));
        assert!(
            derived != reference,
            "near-miss reference must not compare equal"
        );
        Self {
            transcript,
            shared,
            reference,
        }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> [u8; 32] {
        match class {
            Class::Fixed => self.shared,
            Class::Random => bytes(rng),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &[u8; 32]) -> bool {
        ol_pair_qr::chain_key::derive_chain_key(&self.transcript, input) == self.reference
    }
}

// =============================================================== capability

struct CapabilityVerify {
    root: [u8; 32],
    forged: ol_capability::Capability,
    ctx: ol_capability::Context<'static>,
}

impl Harness for CapabilityVerify {
    type Input = ol_capability::RootKey;
    type Output = bool;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        use ol_capability::{Capability, Caveat, Context};
        let root = bytes(rng);
        let key = zeroize::Zeroizing::new(root);
        let cap = Capability::root(bytes(rng), &key)
            .attenuate(Caveat::ExpiresAt(1_000_000))
            .expect("caveat")
            .attenuate(Caveat::PathPrefix("/safe/folder".to_string()))
            .expect("caveat");
        let ctx = Context::new()
            .with_now(500_000)
            .with_path("/safe/folder/x.txt");
        assert!(
            cap.accepts(&key, &ctx),
            "the genuine capability must be accepted"
        );
        let mut wire = cap.encode();
        let last = wire.len() - 1;
        wire[last] ^= 1;
        let forged = Capability::decode(&wire).expect("structurally valid");
        assert!(
            !forged.accepts(&key, &ctx),
            "the forged capability must be rejected"
        );
        Self { root, forged, ctx }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> Self::Input {
        match class {
            Class::Fixed => zeroize::Zeroizing::new(self.root),
            Class::Random => zeroize::Zeroizing::new(bytes(rng)),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &Self::Input) -> bool {
        self.forged.accepts(input, &self.ctx)
    }
}

// =================================================================== duress

const PASSPHRASE_LEN: usize = 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Presented {
    Real,
    Duress,
    Unenrolled,
}

impl Presented {
    const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Real,
            1 => Self::Duress,
            _ => Self::Unenrolled,
        }
    }
}

/// One enrolled account: the gate's three roots and the two enrolled
/// passphrases, with the check hashes account setup stores.
#[derive(Clone)]
struct DuressAccount {
    real_root: [u8; 32],
    duress_root: [u8; 32],
    pair_secret: [u8; 32],
    real: [u8; PASSPHRASE_LEN],
    duress: [u8; PASSPHRASE_LEN],
    unenrolled: [u8; PASSPHRASE_LEN],
    real_check: [u8; 32],
    duress_check: [u8; 32],
}

fn duress_check(domain: &str, root: &[u8; 32], passphrase: &[u8]) -> [u8; 32] {
    let mut input = root.to_vec();
    input.extend_from_slice(passphrase);
    blake3::derive_key(domain, &input)
}

impl DuressAccount {
    fn draw(rng: &mut ChaCha20Rng) -> Self {
        let real_root = bytes(rng);
        let duress_root = bytes(rng);
        let real = bytes(rng);
        let duress = bytes(rng);
        Self {
            real_root,
            duress_root,
            pair_secret: bytes(rng),
            real,
            duress,
            unenrolled: bytes(rng),
            real_check: duress_check("ol-duress-real-check-v1", &real_root, &real),
            duress_check: duress_check("ol-duress-decoy-check-v1", &duress_root, &duress),
        }
    }

    fn input(&self, presented: Presented) -> DuressInput {
        DuressInput {
            gate: ol_duress::DuressGate::new(self.real_root, self.duress_root, self.pair_secret),
            presented: match presented {
                Presented::Real => self.real,
                Presented::Duress => self.duress,
                Presented::Unenrolled => self.unenrolled,
            },
            real_check: self.real_check,
            duress_check: self.duress_check,
        }
    }
}

struct DuressInput {
    gate: ol_duress::DuressGate,
    presented: [u8; PASSPHRASE_LEN],
    real_check: [u8; 32],
    duress_check: [u8; 32],
}

type DuressResult = Result<ol_duress::DuressOutcome, ol_duress::GateError>;

fn duress_open(input: &DuressInput) -> DuressResult {
    input
        .gate
        .open(&input.presented, &input.real_check, &input.duress_check)
}

fn duress_kind(outcome: &DuressResult) -> Presented {
    match outcome {
        Ok(ol_duress::DuressOutcome::Real(_)) => Presented::Real,
        Ok(ol_duress::DuressOutcome::Duress { .. }) => Presented::Duress,
        Err(_) => Presented::Unenrolled,
    }
}

/// Fixed account versus a fresh random account per call, both presented
/// the passphrase `PRESENTED` selects, so both reach the same outcome.
struct DuressOpen<const PRESENTED: u8> {
    account: DuressAccount,
}

impl<const PRESENTED: u8> Harness for DuressOpen<PRESENTED> {
    type Input = DuressInput;
    type Output = DuressResult;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        let presented = Presented::from_code(PRESENTED);
        let account = DuressAccount::draw(rng);
        for sample in [&account, &DuressAccount::draw(rng)] {
            let kind = duress_kind(&duress_open(&sample.input(presented)));
            assert_eq!(kind, presented, "both classes must reach the same outcome");
        }
        Self { account }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> DuressInput {
        let presented = Presented::from_code(PRESENTED);
        match class {
            Class::Fixed => self.account.input(presented),
            Class::Random => DuressAccount::draw(rng).input(presented),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &DuressInput) -> DuressResult {
        duress_open(input)
    }
}

type DuressDecision = Result<ol_duress::GateDecision, ol_duress::GateError>;

/// The gate's uniform decision core (`DuressGate::decide`): the API whose
/// timing must not reveal the outcome. `DuressGate::open` adds the
/// classification into an enum, which branches on the outcome by
/// construction (a duress `open` measured about 1 to 6 TSC ticks slower than
/// a real one), so the across-outcome targets time `decide`.
fn duress_decide(input: &DuressInput) -> DuressDecision {
    input
        .gate
        .decide(&input.presented, &input.real_check, &input.duress_check)
}

fn decided_kind(decision: &DuressDecision) -> Presented {
    let decided = decision
        .as_ref()
        .expect("a non-empty passphrase is always decided");
    Presented::from_code(decided.kind_code())
}

/// The coercion claim itself: a fresh random account per call, class 0
/// presented its real passphrase and class 1 the passphrase `OTHER` selects
/// (1 = duress, 2 = unenrolled). The uniform decision must take the same
/// time for both.
struct DuressRealVs<const OTHER: u8>;

impl<const OTHER: u8> Harness for DuressRealVs<OTHER> {
    type Input = DuressInput;
    type Output = DuressDecision;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        let other = Presented::from_code(OTHER);
        assert_ne!(
            other,
            Presented::Real,
            "the classes must reach different outcomes"
        );
        let account = DuressAccount::draw(rng);
        assert_eq!(
            decided_kind(&duress_decide(&account.input(Presented::Real))),
            Presented::Real
        );
        assert_eq!(decided_kind(&duress_decide(&account.input(other))), other);
        Self
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> DuressInput {
        let account = DuressAccount::draw(rng);
        match class {
            Class::Fixed => account.input(Presented::Real),
            Class::Random => account.input(Presented::from_code(OTHER)),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &DuressInput) -> DuressDecision {
        duress_decide(input)
    }
}

/// Null control paired with `DuressRealVs`: the same two-class harness with
/// both classes presented the REAL passphrase, and class 1 prepared through
/// extra work (a second account drawn and discarded). Its result separates a
/// harness artifact from a difference between outcomes.
struct ControlNullDuress;

impl Harness for ControlNullDuress {
    type Input = DuressInput;
    type Output = DuressDecision;
    fn setup(_rng: &mut ChaCha20Rng) -> Self {
        Self
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> DuressInput {
        if class == Class::Random {
            black_box(DuressAccount::draw(rng));
        }
        DuressAccount::draw(rng).input(Presented::Real)
    }
    #[inline(never)]
    fn run(&mut self, input: &DuressInput) -> DuressDecision {
        duress_decide(input)
    }
}

// ============================================================= confidential

const UNSEAL_TRANSCRIPT: &[u8] = b"probe";

struct ConfidentialUnseal {
    seed: [u8; 32],
    tampered: ol_confidential::SealedKey,
}

impl Harness for ConfidentialUnseal {
    type Input = ol_confidential::SoftwareProvider;
    type Output = ol_confidential::ConfidentialResult<Vec<u8>>;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        use ol_confidential::{ConfidentialProvider, SoftwareProvider};
        let seed = bytes(rng);
        let provider = SoftwareProvider::generate(&mut ChaCha20Rng::from_seed(seed));
        let sealed = provider.seal_master(&bytes(rng)).expect("seal");
        assert!(
            provider.sealed_sign(&sealed, UNSEAL_TRANSCRIPT).is_ok(),
            "the fixed provider must own the sealed blob"
        );
        let mut tampered = sealed.clone();
        let last = tampered.bytes.len() - 1;
        tampered.bytes[last] ^= 0x80;
        assert!(provider.sealed_sign(&tampered, UNSEAL_TRANSCRIPT).is_err());
        let other = SoftwareProvider::generate(rng);
        assert!(other.sealed_sign(&tampered, UNSEAL_TRANSCRIPT).is_err());
        Self { seed, tampered }
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> Self::Input {
        use ol_confidential::SoftwareProvider;
        match class {
            Class::Fixed => SoftwareProvider::generate(&mut ChaCha20Rng::from_seed(self.seed)),
            Class::Random => SoftwareProvider::generate(rng),
        }
    }
    #[inline(never)]
    fn run(&mut self, input: &Self::Input) -> Self::Output {
        use ol_confidential::ConfidentialProvider;
        input.sealed_sign(&self.tampered, UNSEAL_TRANSCRIPT)
    }
}

// ==================================================================== pqkem

/// FIPS 203 ML-KEM-768 decapsulation key (2400 bytes) followed by One
/// Link's 32-byte X25519 scalar: `s_hat` and `z` and the scalar are secret;
/// `ek` (1152..2336) and `H(ek)` (2336..2368) are public.
const S_HAT: Range<usize> = 0..1152;
const Z: Range<usize> = 2368..2400;
const X25519_SCALAR: Range<usize> = 2400..2432;
const _: () = assert!(ol_pqkem::HYBRID_SECRET_KEY_LEN == 2432);
const KEY_POOL: usize = 512;

/// The fixed key against keys whose secret parts (`s_hat` from a genuine
/// key, fresh `z` and X25519 scalar) are random but whose public `ek` and
/// `H(ek)` are the fixed key's: the same public matrix work in both classes.
/// `MALFORMED = false`: a valid ciphertext for the fixed key, so class 0
/// takes the success path and class 1 the implicit-rejection path (the
/// FO comparison result is secret). `MALFORMED = true`: a tampered
/// ciphertext, rejected in both classes.
struct PqKemDecap<const MALFORMED: bool> {
    fixed: Vec<u8>,
    pool: Vec<[u8; 1152]>,
    ct: ol_pqkem::HybridCiphertext,
}

impl<const MALFORMED: bool> PqKemDecap<MALFORMED> {
    fn spliced(&self, rng: &mut ChaCha20Rng) -> [u8; ol_pqkem::HYBRID_SECRET_KEY_LEN] {
        let mut wire = [0u8; ol_pqkem::HYBRID_SECRET_KEY_LEN];
        wire.copy_from_slice(&self.fixed);
        wire[S_HAT].copy_from_slice(pick(&self.pool, rng));
        rng.fill_bytes(&mut wire[Z]);
        rng.fill_bytes(&mut wire[X25519_SCALAR]);
        wire
    }
}

impl<const MALFORMED: bool> Harness for PqKemDecap<MALFORMED> {
    type Input = ol_pqkem::HybridSecretKey;
    type Output = Result<ol_pqkem::SharedSecret, ol_pqkem::PqKemError>;
    fn setup(rng: &mut ChaCha20Rng) -> Self {
        use ol_pqkem::{decapsulate, encapsulate, keypair, HybridCiphertext, HybridSecretKey};
        let (pk, sk) = keypair(rng);
        let (ct, shared) = encapsulate(&pk, rng).expect("encapsulate");
        let ct = if MALFORMED {
            let mut wire = ct.to_bytes();
            wire[17] ^= 0xff;
            HybridCiphertext::from_bytes(&wire).expect("structurally valid")
        } else {
            ct
        };
        let fixed = sk.to_bytes().to_vec();
        let pool = (0..KEY_POOL)
            .map(|_| {
                let (_, other) = keypair(rng);
                let wire = other.to_bytes();
                let mut s_hat = [0u8; 1152];
                s_hat.copy_from_slice(&wire[S_HAT]);
                s_hat
            })
            .collect();
        let harness = Self { fixed, pool, ct };
        let fixed_ss = decapsulate(&sk, &harness.ct).expect("implicit rejection never errors");
        assert_eq!(*fixed_ss == *shared, !MALFORMED, "class 0 path");
        let spliced = HybridSecretKey::from_bytes(&harness.spliced(rng)).expect("round trip");
        let spliced_ss =
            decapsulate(&spliced, &harness.ct).expect("implicit rejection never errors");
        assert!(
            *spliced_ss != *shared,
            "class 1 must take implicit rejection"
        );
        harness
    }
    fn input(&mut self, class: Class, rng: &mut ChaCha20Rng) -> Self::Input {
        let parsed = match class {
            Class::Fixed => ol_pqkem::HybridSecretKey::from_bytes(&self.fixed),
            Class::Random => ol_pqkem::HybridSecretKey::from_bytes(&self.spliced(rng)),
        };
        parsed.expect("well-formed secret key")
    }
    #[inline(never)]
    fn run(&mut self, input: &Self::Input) -> Self::Output {
        ol_pqkem::decapsulate(input, &self.ct)
    }
}

// ==================================================================== table

/// A timing target.
pub(crate) struct Target {
    pub(crate) name: &'static str,
    pub(crate) expect: Expect,
    /// Valgrind audit cases whose secret dataflow this target qualifies.
    pub(crate) covers: &'static [&'static str],
    pub(crate) what: &'static str,
    pub(crate) secret: &'static str,
    pub(crate) fixed: &'static str,
    pub(crate) random: &'static str,
    pub(crate) calls: usize,
    measure: fn(&Target, &Config) -> Outcome,
}

pub(crate) const TARGETS: &[Target] = &[
    Target {
        name: "control_early_exit_compare",
        expect: Expect::Leak,
        covers: &[],
        what: "negative control: a byte-at-a-time compare that returns at the first differing byte",
        secret: "a 32-byte value compared with a public probe",
        fixed: "one random 32-byte value; the probe equals it except in the last byte (32 bytes scanned)",
        random: "uniform 32-byte values (the first byte differs with probability 255/256)",
        calls: 16,
        measure: measure::<ControlEarlyExit>,
    },
    Target {
        name: "control_table_lookup",
        expect: Expect::Leak,
        covers: &[],
        what: "negative control: production gf_mul_fast, a secret-indexed 64 KiB table (cache timing)",
        secret: "both GF(2^8) operands (the table index)",
        fixed: "(0, 0): one table line",
        random: "uniform operand pairs: uniform over the 64 KiB table",
        calls: 32,
        measure: measure::<ControlTableLookup>,
    },
    Target {
        name: "control_null_prep_asymmetry",
        expect: Expect::Null,
        covers: &[],
        what: "null control: gf_mul on uniform operands in both classes, class 1 prepared through a heavier path",
        secret: "none (both classes are uniform operand pairs)",
        fixed: "class 0: uniform operand pairs drawn directly",
        random: "class 1: uniform operand pairs taken from a BLAKE3 hash, after a 1 KiB scratch-memory sweep",
        calls: 32,
        measure: measure::<ControlNullPrep>,
    },
    Target {
        name: "threshold_gf_mul",
        expect: Expect::ConstantTime,
        covers: &["threshold_gf_mul"],
        what: "GF(2^8) multiply of two secret operands",
        secret: "both operands",
        fixed: "(0, 0): a zero multiplier, where an early-terminating loop would stop at once",
        random: "uniform operand pairs",
        calls: 32,
        measure: measure::<GfMul>,
    },
    Target {
        name: "threshold_gf_inv",
        expect: Expect::ConstantTime,
        covers: &["threshold_gf_inv"],
        what: "GF(2^8) inverse of a secret operand",
        secret: "the operand",
        fixed: "0 (the conventional inverse of zero, the special case a zero test would branch on)",
        random: "uniform bytes",
        calls: 4,
        measure: measure::<GfInv>,
    },
    Target {
        name: "threshold_share_byte",
        expect: Expect::ConstantTime,
        covers: &["threshold_share_byte"],
        what: "Shamir 3-of-5 split of a secret byte with a secret coefficient stream",
        secret: "the shared byte and the PRNG state that draws the coefficients",
        fixed: "byte 0 with one fixed PRNG state (so one fixed coefficient vector)",
        random: "a uniform byte with a PRNG state seeded from a uniform 64-bit seed",
        calls: 2,
        measure: measure::<ShareByte>,
    },
    Target {
        name: "onion_hop_id_eq",
        expect: Expect::ConstantTime,
        covers: &["onion_hop_id_eq"],
        what: "HopId equality (subtle::ConstantTimeEq) of a secret id with a public probe",
        secret: "the 32-byte HopId",
        fixed: "one random id; the probe equals it except in the last byte (both classes unequal)",
        random: "uniform ids",
        calls: 16,
        measure: measure::<HopIdEq>,
    },
    Target {
        name: "onion_layer_key_eq",
        expect: Expect::ConstantTime,
        covers: &["onion_layer_key_eq"],
        what: "LayerKey equality (subtle::ConstantTimeEq) of a secret key with a public probe",
        secret: "the 32-byte layer key",
        fixed: "one random key; the probe equals it except in the last byte (both classes unequal)",
        random: "uniform keys",
        calls: 16,
        measure: measure::<LayerKeyEq>,
    },
    Target {
        name: "pair_qr_transcript_ct_eq",
        expect: Expect::ConstantTime,
        covers: &["pair_qr_transcript_ct_eq"],
        what: "TranscriptHash::ct_eq of a secret transcript hash with a public probe",
        secret: "the 32-byte transcript hash",
        fixed: "one random hash; the probe equals it except in the last byte (both classes unequal)",
        random: "uniform hashes",
        calls: 16,
        measure: measure::<TranscriptCtEq>,
    },
    Target {
        name: "pair_qr_chain_key",
        expect: Expect::ConstantTime,
        covers: &["pair_qr_chain_key"],
        what: "chain-key derivation from a secret X25519 shared secret and its comparison",
        secret: "the 32-byte X25519 shared secret",
        fixed: "one random shared secret; the reference chain key equals its derivation except in the last byte",
        random: "uniform shared secrets (the derived key differs from the reference throughout)",
        calls: 2,
        measure: measure::<ChainKeyEq>,
    },
    Target {
        name: "quic_server_cert_fingerprint",
        expect: Expect::ConstantTime,
        covers: &["quic_server_cert_fingerprint"],
        what: "the dialer's server-certificate fingerprint check (X.509 parse + constant-time compare); both classes reject",
        secret: "the 32-byte fingerprint the dialer expects",
        fixed: "the presented certificate's fingerprint with its last byte flipped (an early-exit compare would scan all 32 bytes)",
        random: "uniform fingerprints (an early-exit compare would stop at the first byte)",
        calls: 1,
        measure: measure::<QuicServerCertFingerprint>,
    },
    Target {
        name: "onion_header_mac_verify",
        expect: Expect::ConstantTime,
        covers: &["onion_header_mac_verify"],
        what: "Sphinx header MAC verification (keyed BLAKE3 + constant-time tag compare)",
        secret: "the 32-byte MAC key",
        fixed: "one random key; the presented tag is that key's MAC with the last byte flipped",
        random: "uniform keys (the presented tag mismatches from the first byte); both classes reject",
        calls: 1,
        measure: measure::<HeaderMacVerify>,
    },
    Target {
        name: "capability_verify",
        expect: Expect::ConstantTime,
        covers: &["capability_verify"],
        what: "capability HMAC-chain verification of a forged two-caveat capability",
        secret: "the 32-byte root key",
        fixed: "the root key that minted the capability; its signature's last byte is flipped",
        random: "uniform root keys; both classes are rejected at the signature compare",
        calls: 1,
        measure: measure::<CapabilityVerify>,
    },
    Target {
        name: "confidential_unseal_tampered",
        expect: Expect::ConstantTime,
        covers: &["confidential_unseal_tampered"],
        what: "sealed-key unseal (ChaCha20-Poly1305) of a blob tampered in its last tag byte",
        secret: "the provider's AEAD key",
        fixed: "the provider that sealed the blob (the tag compare differs in the last byte only)",
        random: "providers generated from uniform seeds; both classes fail authentication",
        calls: 1,
        measure: measure::<ConfidentialUnseal>,
    },
    Target {
        name: "obfs_server_accept_forged",
        expect: Expect::ConstantTime,
        covers: &["obfs_server_accept"],
        what: "obfs bridge accept of a prober's forged first message (rejected at the MAC)",
        secret: "the bridge id (the handshake MAC key) and the bridge's static X25519 secret",
        fixed: "one bridge; the message is its genuine first message with the last tag byte flipped",
        random: "bridges with uniform id and secret (1024-bridge pool); both classes reject",
        calls: 1,
        measure: measure::<ObfsAccept<false>>,
    },
    Target {
        name: "duress_open_real",
        expect: Expect::ConstantTime,
        covers: &["duress_open_real"],
        what: "duress gate presented the account's real passphrase",
        secret: "the three gate roots, both enrolled passphrases and their check hashes",
        fixed: "one random account",
        random: "a fresh uniform account per call; both classes open the real volume",
        calls: 1,
        measure: measure::<DuressOpen<0>>,
    },
    Target {
        name: "duress_open_duress",
        expect: Expect::ConstantTime,
        covers: &["duress_open_duress"],
        what: "duress gate presented the account's duress passphrase",
        secret: "the three gate roots, both enrolled passphrases and their check hashes",
        fixed: "one random account",
        random: "a fresh uniform account per call; both classes open the decoy volume",
        calls: 1,
        measure: measure::<DuressOpen<1>>,
    },
    Target {
        name: "duress_open_rejected",
        expect: Expect::ConstantTime,
        covers: &["duress_open_rejected"],
        what: "duress gate presented an unenrolled passphrase",
        secret: "the three gate roots, both enrolled passphrases and their check hashes",
        fixed: "one random account",
        random: "a fresh uniform account per call; both classes are rejected",
        calls: 1,
        measure: measure::<DuressOpen<2>>,
    },
    Target {
        name: "duress_real_vs_duress",
        expect: Expect::ConstantTime,
        covers: &["duress_decide_real", "duress_decide_duress"],
        what: "the coercion claim: the gate's uniform decision (DuressGate::decide) for a real and for a duress passphrase must be indistinguishable by timing",
        secret: "which enrolled passphrase was presented (and the account's roots)",
        fixed: "class 0: a fresh uniform account per call, presented its REAL passphrase",
        random: "class 1: a fresh uniform account per call, presented its DURESS passphrase",
        calls: 1,
        measure: measure::<DuressRealVs<1>>,
    },
    Target {
        name: "duress_real_vs_rejected",
        expect: Expect::ConstantTime,
        covers: &["duress_decide_rejected"],
        what: "the uniform decision for a real passphrase and for an unenrolled one must be indistinguishable by timing",
        secret: "whether the presented passphrase is enrolled (and the account's roots)",
        fixed: "class 0: a fresh uniform account per call, presented its REAL passphrase",
        random: "class 1: a fresh uniform account per call, presented an UNENROLLED passphrase",
        calls: 1,
        measure: measure::<DuressRealVs<2>>,
    },
    Target {
        name: "control_null_duress_real_vs_real",
        expect: Expect::Null,
        covers: &[],
        what: "null control for the duress across-outcome targets: the same harness, both classes presented the REAL passphrase",
        secret: "none distinguishes the classes (both are fresh uniform accounts opened with the real passphrase)",
        fixed: "class 0: a fresh uniform account per call, presented its REAL passphrase",
        random: "class 1: the same, after drawing and discarding one extra account",
        calls: 1,
        measure: measure::<ControlNullDuress>,
    },
    Target {
        name: "obfs_server_accept_valid",
        expect: Expect::ConstantTime,
        covers: &["obfs_server_accept"],
        what: "obfs bridge accept of a genuine first message (ECDH + session derivation)",
        secret: "the bridge's static X25519 secret",
        fixed: "one bridge secret",
        random: "uniform secrets sharing the fixed bridge id (1024-bridge pool); both classes accept",
        calls: 1,
        measure: measure::<ObfsAccept<true>>,
    },
    Target {
        name: "pqkem_decapsulate_valid",
        expect: Expect::ConstantTime,
        covers: &["pqkem_decapsulate_valid"],
        what: "hybrid ML-KEM-768 + X25519 decapsulation: success path against implicit rejection",
        secret: "s_hat, z and the X25519 scalar (ek and H(ek) are public and shared by both classes)",
        fixed: "one genuine key; the ciphertext is a valid encapsulation to it (success path)",
        random: "s_hat from a 512-key pool of genuine keys, uniform z and scalar, the fixed key's ek (implicit rejection)",
        calls: 1,
        measure: measure::<PqKemDecap<false>>,
    },
    Target {
        name: "pqkem_decapsulate_malformed",
        expect: Expect::ConstantTime,
        covers: &["pqkem_decapsulate_malformed"],
        what: "hybrid decapsulation of a tampered ciphertext (implicit rejection in both classes)",
        secret: "s_hat, z and the X25519 scalar (ek and H(ek) are public and shared by both classes)",
        fixed: "one genuine key",
        random: "s_hat from a 512-key pool of genuine keys, uniform z and scalar, the fixed key's ek",
        calls: 1,
        measure: measure::<PqKemDecap<true>>,
    },
];

// ===================================================================== JSON

fn num(x: f64) -> String {
    if x.is_finite() {
        format!("{x}")
    } else {
        "null".to_string()
    }
}

fn opt_num(x: Option<f64>) -> String {
    x.map_or_else(|| "null".to_string(), num)
}

fn quoted(text: &str) -> String {
    format!("\"{}\"", json_escape(text))
}

fn array<T>(items: impl IntoIterator<Item = T>, render: impl Fn(T) -> String) -> String {
    let parts: Vec<String> = items.into_iter().map(render).collect();
    format!("[{}]", parts.join(","))
}

fn expect_str(expect: Expect) -> &'static str {
    match expect {
        Expect::ConstantTime => "constant_time",
        Expect::Leak => "leak",
        Expect::Null => "null",
    }
}

fn describe(target: &Target) -> String {
    format!(
        "{{\"name\":{},\"expect\":\"{}\",\"covers\":{},\"what\":{},\"secret\":{},\"fixed\":{},\"random\":{},\"calls_per_measurement\":{}}}",
        quoted(target.name),
        expect_str(target.expect),
        array(target.covers.iter(), |c| quoted(c)),
        quoted(target.what),
        quoted(target.secret),
        quoted(target.fixed),
        quoted(target.random),
        target.calls
    )
}

fn crops_json(rows: &[CropRow]) -> String {
    let column = |f: &dyn Fn(&CropRow) -> String| array(rows.iter(), f);
    format!(
        "{{\"percentile\":{},\"threshold\":{},\"n_fixed\":{},\"n_random\":{},\"mean_fixed\":{},\"mean_random\":{},\"var_fixed\":{},\"var_random\":{},\"t\":{},\"mde\":{},\"sensitivity\":{},\"mde_shift\":{}}}",
        column(&|r| opt_num(r.percentile)),
        column(&|r| r.threshold.map_or_else(|| "null".to_string(), |t| t.to_string())),
        column(&|r| r.fixed.n.to_string()),
        column(&|r| r.random.n.to_string()),
        column(&|r| num(r.fixed.mean)),
        column(&|r| num(r.random.mean)),
        column(&|r| num(r.fixed.variance())),
        column(&|r| num(r.random.variance())),
        column(&|r| opt_num(r.t)),
        column(&|r| opt_num(r.mde)),
        column(&|r| num(r.sensitivity)),
        column(&|r| opt_num(r.mde_shift)),
    )
}

fn quantiles_json(thinned: &Thinned) -> String {
    let sorted = thinned.sorted();
    if sorted.is_empty() {
        return "null".to_string();
    }
    array(REPORTED_QUANTILES, |q| percentile(&sorted, q).to_string())
}

fn headline_json(head: Option<Headline>, calls: usize, net_median: u64) -> String {
    let Some(h) = head else {
        return "null".to_string();
    };
    let calls = usize_to_f64(calls);
    let net = to_f64(net_median);
    format!(
        "{{\"row\":{},\"mde\":{},\"mde_per_call\":{},\"mde_fraction\":{},\"mde80\":{},\"mde80_per_call\":{},\"mde80_fraction\":{}}}",
        h.row,
        num(h.mde),
        num(h.mde / calls),
        num(h.mde / net),
        num(h.mde80),
        num(h.mde80 / calls),
        num(h.mde80 / net)
    )
}

/// The verdict and the numbers it rests on, as one JSON object.
pub(crate) fn result_json(
    target: &Target,
    cfg: &Config,
    outcome: &Outcome,
) -> (String, &'static str) {
    let rows = outcome.acc.rows(&outcome.percentiles);
    let net_median = net_median(&outcome.thinned, outcome.clock_overhead);
    let peak = max_abs_t(&rows);
    let quantum = reading_quantum(outcome.thinned.iter().flat_map(|t| &t.values));
    let head = headline(&rows, quantum);
    let verdict = verdict(
        peak.map(|p| p.1),
        head.map(|h| h.mde80 / to_f64(net_median)),
        cfg.mde_bound,
    );
    let mut out = String::with_capacity(16 * 1024);
    let _ = write!(
        out,
        "{{\"schema\":\"one-link/ct-timing-target/v1\",\"target\":{},\"clock\":{},\"unit\":{},\"ticks_per_second\":{},",
        describe(target),
        quoted(clock::NAME),
        quoted(clock::UNIT),
        num(outcome.ticks_per_second)
    );
    let _ = write!(
        out,
        "\"config\":{{\"seed\":{},\"budget_ms\":{},\"min_time_ms\":{},\"min_measurements\":{},\"mde_goal\":{},\"mde_bound\":{},\"t_threshold\":{},\"decisive_t\":{},\"power\":0.8,\"z_power\":{},\"min_class_n\":{},\"min_sensitivity\":{},\"batch\":{},\"discard_per_batch\":{}}},",
        cfg.seed,
        cfg.budget.as_millis(),
        cfg.min_time.as_millis(),
        cfg.min_measurements,
        num(cfg.mde_goal),
        num(cfg.mde_bound),
        num(T_THRESHOLD),
        num(DECISIVE_T),
        num(Z_POWER_80),
        MIN_CLASS_N,
        num(MIN_SENSITIVITY),
        outcome.batch,
        DISCARD_PER_BATCH.min(outcome.batch / 4)
    );
    let _ = write!(
        out,
        "\"warmup_measurements\":{},\"calibration_measurements\":{},\"calibration_median\":{},\"elapsed_ms\":{},\"stop_reason\":\"{}\",\"clock_overhead\":{},\"reading_quantum\":{},\"net_median\":{},\"fraction_of\":\"the smaller class median of the run, net of the clock overhead\",",
        outcome.warmup,
        outcome.calibration,
        outcome.calibration_median,
        outcome.elapsed.as_millis(),
        outcome.stop.as_str(),
        outcome.clock_overhead,
        quantum,
        net_median
    );
    let _ = write!(
        out,
        "\"quantiles\":{{\"levels\":{},\"fixed\":{},\"random\":{},\"sample_stride\":[{},{}]}},",
        array(REPORTED_QUANTILES, num),
        quantiles_json(&outcome.thinned[0]),
        quantiles_json(&outcome.thinned[1]),
        outcome.thinned[0].stride,
        outcome.thinned[1].stride
    );
    let _ = write!(
        out,
        "\"measurements\":{{\"fixed\":{},\"random\":{},\"excluded_anomalies\":{}}},\"max_abs_t\":{},\"max_abs_t_row\":{},\"headline\":{},\"verdict\":\"{}\",",
        outcome.acc.total(Class::Fixed),
        outcome.acc.total(Class::Random),
        outcome.anomalies,
        opt_num(peak.map(|p| p.1)),
        peak.map_or_else(|| "null".to_string(), |p| p.0.to_string()),
        headline_json(head, target.calls, net_median),
        verdict
    );
    let _ = write!(
        out,
        "\"crops\":{},\"histogram\":{{\"min\":{},\"max\":{},\"fixed\":{},\"random\":{}}}}}",
        crops_json(&rows),
        outcome.acc.min,
        outcome.acc.max,
        array(outcome.acc.histogram(Class::Fixed), |c| c.to_string()),
        array(outcome.acc.histogram(Class::Random), |c| c.to_string())
    );
    (out, verdict)
}

// ====================================================================== CLI

const USAGE: &str = "usage: ol_ct_audit --dudect-list\n       ol_ct_audit --dudect <target> | --dudect-all [--budget-ms N] [--min-time-ms N] [--min-measurements N] [--mde-goal F] [--mde-bound F] [--seed N]";

enum Command {
    List,
    Run(Vec<&'static Target>, Config),
}

fn value<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, String> {
    args.get(i + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn parse_u64(text: &str, flag: &str) -> Result<u64, String> {
    text.parse()
        .map_err(|_| format!("{flag}: not an unsigned integer: {text}"))
}

fn parse_fraction(text: &str, flag: &str) -> Result<f64, String> {
    let parsed: f64 = text
        .parse()
        .map_err(|_| format!("{flag}: not a number: {text}"))?;
    if parsed > 0.0 && parsed < 1.0 {
        Ok(parsed)
    } else {
        Err(format!("{flag}: must lie strictly between 0 and 1: {text}"))
    }
}

fn default_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let folded = u64::try_from(nanos & u128::from(u64::MAX)).unwrap_or(0);
    folded ^ u64::from(std::process::id()).rotate_left(32)
}

fn parse(args: &[String]) -> Result<Command, String> {
    let mut cfg = Config {
        budget: Duration::from_secs(30),
        min_time: Duration::from_secs(5),
        min_measurements: 200_000,
        mde_goal: 0.001,
        mde_bound: 0.01,
        seed: default_seed(),
    };
    let mut selected: Option<Vec<&'static Target>> = None;
    let mut list = false;
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let mut takes_value = true;
        match flag {
            "--dudect-list" => {
                list = true;
                takes_value = false;
            }
            "--dudect-all" => {
                selected = Some(TARGETS.iter().collect());
                takes_value = false;
            }
            "--dudect" => {
                let name = value(args, i, flag)?;
                let target = TARGETS
                    .iter()
                    .find(|t| t.name == name)
                    .ok_or_else(|| format!("unknown timing target {name}"))?;
                selected = Some(vec![target]);
            }
            "--budget-ms" => {
                cfg.budget = Duration::from_millis(parse_u64(value(args, i, flag)?, flag)?);
            }
            "--min-time-ms" => {
                cfg.min_time = Duration::from_millis(parse_u64(value(args, i, flag)?, flag)?);
            }
            "--min-measurements" => cfg.min_measurements = parse_u64(value(args, i, flag)?, flag)?,
            "--mde-goal" => cfg.mde_goal = parse_fraction(value(args, i, flag)?, flag)?,
            "--mde-bound" => cfg.mde_bound = parse_fraction(value(args, i, flag)?, flag)?,
            "--seed" => cfg.seed = parse_u64(value(args, i, flag)?, flag)?,
            other => return Err(format!("unknown argument {other}")),
        }
        i += if takes_value { 2 } else { 1 };
    }
    if list {
        return Ok(Command::List);
    }
    let targets = selected.ok_or("give --dudect <target>, --dudect-all or --dudect-list")?;
    if cfg.budget.is_zero() {
        return Err("--budget-ms must be positive".to_string());
    }
    Ok(Command::Run(targets, cfg))
}

/// Entry point for the `--dudect*` modes. Exit 0: every result as expected
/// (constant-time targets PASS, controls LEAK); 1: an unexpected verdict (a
/// leak, or a control not detected); 4: otherwise some target was
/// INCONCLUSIVE-POWER; 2: usage error.
pub(crate) fn main(args: &[String]) -> ExitCode {
    let command = match parse(args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("ol_ct_audit: {message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let (targets, cfg) = match command {
        Command::List => {
            for target in TARGETS {
                println!("{}", describe(target));
            }
            return ExitCode::SUCCESS;
        }
        Command::Run(targets, cfg) => (targets, cfg),
    };
    let mut unexpected = false;
    let mut inconclusive = false;
    for target in targets {
        let outcome = (target.measure)(target, &cfg);
        let (json, verdict) = result_json(target, &cfg, &outcome);
        println!("{json}");
        match (target.expect, verdict) {
            (Expect::ConstantTime | Expect::Null, VERDICT_PASS) | (Expect::Leak, VERDICT_LEAK) => {}
            (Expect::ConstantTime | Expect::Null, VERDICT_INCONCLUSIVE) => inconclusive = true,
            _ => unexpected = true,
        }
    }
    if unexpected {
        ExitCode::from(1)
    } else if inconclusive {
        ExitCode::from(4)
    } else {
        ExitCode::SUCCESS
    }
}

// ==================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;

    fn moments(values: &[f64]) -> Moments {
        let mut m = Moments::default();
        for &v in values {
            m.push(v);
        }
        m
    }

    fn close(a: f64, b: f64, tolerance: f64) -> bool {
        (a - b).abs() <= tolerance * b.abs().max(1.0)
    }

    /// A deterministic, irregular sample (no RNG crate needed).
    fn sample(n: usize, seed: u64, scale: f64) -> Vec<f64> {
        let mut state = seed;
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                to_f64(state >> 40) / to_f64(1 << 24) * scale
            })
            .collect()
    }

    #[test]
    fn welford_and_merge_match_the_two_pass_formulas() {
        let values = sample(5_000, 7, 1_000.0);
        let mean = values.iter().sum::<f64>() / usize_to_f64(values.len());
        let var =
            values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / usize_to_f64(values.len() - 1);
        let whole = moments(&values);
        assert_eq!(whole.n, 5_000);
        assert!(close(whole.mean, mean, 1e-12));
        assert!(close(whole.variance(), var, 1e-10));
        let (left, right) = values.split_at(1_234);
        let merged = moments(left).merge(moments(right));
        assert_eq!(merged.n, whole.n);
        assert!(close(merged.mean, whole.mean, 1e-12));
        assert!(close(merged.variance(), whole.variance(), 1e-10));
    }

    #[test]
    fn welch_t_matches_hand_derived_values() {
        // a: mean 3, var 2.5; b: mean 6, var 10; se = sqrt(2.5/5 + 10/5).
        let a = moments(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        let b = moments(&[2.0, 4.0, 6.0, 8.0, 10.0]);
        let t = welch_t(&a, &b).expect("defined");
        assert!(close(t, 3.0 / 2.5_f64.sqrt(), 1e-12), "{t}");
        assert!(close(t, 1.897_366_596_101_027_5, 1e-12));
        assert!(close(welch_t(&b, &a).expect("defined"), -t, 1e-12));
        // Unequal sizes: a: mean 2, var 1 (n 3); b: mean 8, var 10 (n 5).
        let a = moments(&[1.0, 2.0, 3.0]);
        let b = moments(&[4.0, 6.0, 8.0, 10.0, 12.0]);
        let t = welch_t(&a, &b).expect("defined");
        assert!(close(t, 6.0 / (1.0 / 3.0 + 2.0_f64).sqrt(), 1e-12), "{t}");
        // Undefined below two samples or with no variance at all.
        assert_eq!(welch_t(&moments(&[1.0]), &b), None);
        assert_eq!(welch_t(&moments(&[2.0, 2.0]), &moments(&[2.0, 2.0])), None);
    }

    #[test]
    fn a_shift_of_exactly_the_mde_gives_t_equal_to_the_threshold() {
        let a = sample(20_000, 11, 500.0);
        let b = sample(30_000, 13, 900.0);
        let (ma, mb) = (moments(&a), moments(&b));
        let mde = minimum_detectable_effect(&ma, &mb, T_THRESHOLD).expect("defined");
        assert!(mde > 0.0);
        // Move b so its mean is exactly `mde` above a's; variances unchanged.
        let offset = ma.mean + mde - mb.mean;
        let shifted: Vec<f64> = b.iter().map(|v| v + offset).collect();
        let t = welch_t(&ma, &moments(&shifted)).expect("defined");
        assert!(close(t, T_THRESHOLD, 1e-9), "{t}");
        // Half the shift is half the statistic: the MDE is linear in se.
        let half: Vec<f64> = b
            .iter()
            .map(|v| v + ma.mean + mde / 2.0 - mb.mean)
            .collect();
        let t_half = welch_t(&ma, &moments(&half)).expect("defined");
        assert!(close(t_half, T_THRESHOLD / 2.0, 1e-9), "{t_half}");
    }

    #[test]
    fn the_power_margin_is_the_80_percent_normal_quantile() {
        // Simpson's rule for Phi(z) from -10: must be 0.8 at Z_POWER_80.
        let pdf = |x: f64| (-0.5 * x * x).exp() / (2.0 * std::f64::consts::PI).sqrt();
        let (lo, hi, steps) = (-10.0, Z_POWER_80, 200_000_u32);
        let h = (hi - lo) / f64::from(steps);
        let mut acc = pdf(lo) + pdf(hi);
        for i in 1..steps {
            let weight = if i % 2 == 1 { 4.0 } else { 2.0 };
            acc += weight * pdf(lo + f64::from(i) * h);
        }
        assert!(close(acc * h / 3.0, 0.8, 1e-9));
        let mde80 = mde_at_80_percent_power(2.0, T_THRESHOLD);
        assert!(close(mde80, 2.0 * (4.5 + Z_POWER_80) / 4.5, 1e-15));
    }

    #[test]
    fn crops_are_strictly_below_their_threshold_and_dudect_spaced() {
        let percentiles = dudect_percentiles();
        assert_eq!(percentiles.len(), NUMBER_PERCENTILES);
        assert!(close(percentiles[0], 1.0 - 0.5_f64.powf(0.1), 1e-15));
        assert!(close(percentiles[9], 0.5, 1e-15));
        assert!(close(percentiles[99], 1.0 - 0.5_f64.powi(10), 1e-15));
        let mut acc = CropAccumulator::new(vec![10, 20]);
        for (class, x) in [(Class::Fixed, 5), (Class::Fixed, 10), (Class::Random, 19)] {
            acc.push(class, x);
        }
        acc.push(Class::Random, 20);
        acc.push(Class::Fixed, 25);
        let rows = acc.rows(&[0.25, 0.5]);
        assert_eq!((rows[0].fixed.n, rows[0].random.n), (3, 2));
        assert_eq!((rows[1].fixed.n, rows[1].random.n), (1, 0));
        assert_eq!((rows[2].fixed.n, rows[2].random.n), (2, 1));
        assert!(close(rows[2].fixed.mean, 7.5, 1e-15));
        assert_eq!(acc.histogram(Class::Fixed), vec![1, 1, 1]);
        assert_eq!(acc.histogram(Class::Random), vec![0, 1, 1]);
    }

    #[test]
    fn the_shift_sensitivity_matches_an_actual_shift() {
        // Uniform 0..10000: below the median a shift d moves the crop mean
        // by d / 2 (s = 1 - (1/10000) (5000 - 2499.5) / 0.5 = 0.49995).
        let values: Vec<u64> = (0..200_000_u64).map(|i| i % 10_000).collect();
        let mut sorted = values.clone();
        sorted.sort_unstable();
        let percentiles = dudect_percentiles();
        let thresholds: Vec<u64> = percentiles
            .iter()
            .map(|&p| percentile(&sorted, p))
            .collect();
        let mut acc = CropAccumulator::new(thresholds.clone());
        for (i, &v) in values.iter().enumerate() {
            acc.push(
                if i % 2 == 0 {
                    Class::Fixed
                } else {
                    Class::Random
                },
                v,
            );
        }
        let rows = acc.rows(&percentiles);
        assert!(close(rows[0].sensitivity, 1.0, 0.0));
        let median = &rows[10];
        assert_eq!(median.threshold, Some(5_000));
        assert!(
            (median.sensitivity - 0.5).abs() < 0.01,
            "{}",
            median.sensitivity
        );
        // Empirical check: shift every value by d and re-crop at the same
        // threshold; the crop mean moves by s * d.
        let d = 40;
        let crop_mean = |shift: u64| {
            let kept: Vec<f64> = values
                .iter()
                .map(|v| v + shift)
                .filter(|&v| v < 5_000)
                .map(to_f64)
                .collect();
            kept.iter().sum::<f64>() / usize_to_f64(kept.len())
        };
        let moved = (crop_mean(d) - crop_mean(0)) / to_f64(d);
        assert!(
            (moved - median.sensitivity).abs() < 0.01,
            "{moved} vs {}",
            median.sensitivity
        );
        let head = headline(&rows, 1).expect("power is defined");
        // A crop narrower than the clock quantum backs no power claim.
        assert_eq!(headline(&rows, 1_000_000), None);
        assert_eq!(reading_quantum(&[6, 10, 14]), 2);
        assert_eq!(reading_quantum(&[6, 9]), 3);
        assert_eq!(reading_quantum(&[]), 1);
        let best = &rows[head.row];
        assert!(close(
            head.mde,
            best.mde.expect("mde") / best.sensitivity.abs(),
            1e-12
        ));
    }

    #[test]
    fn the_thinned_sample_stays_systematic_and_bounded() {
        let mut thinned = Thinned::new();
        for x in 0..200_000_u64 {
            thinned.push(x);
        }
        assert!(thinned.values.len() < THINNED_CAPACITY);
        assert!(thinned.stride > 1);
        assert!(thinned.values.iter().all(|v| v % thinned.stride == 0));
        let sorted = thinned.sorted();
        let median = percentile(&sorted, 0.5);
        assert!(median.abs_diff(100_000) <= thinned.stride, "{median}");
        // A crop is never credited with more power than its own MDE.
        assert!(close(effective_sensitivity(-1.7), 1.0, 0.0));
        assert!(close(effective_sensitivity(-0.4), 0.4, 0.0));
    }

    #[test]
    fn verdicts_follow_t_then_power() {
        assert_eq!(verdict(Some(4.51), Some(0.0001), 0.01), VERDICT_LEAK);
        assert_eq!(verdict(Some(4.5), Some(0.0001), 0.01), VERDICT_PASS);
        assert_eq!(verdict(Some(1.0), Some(0.02), 0.01), VERDICT_INCONCLUSIVE);
        assert_eq!(verdict(None, None, 0.01), VERDICT_INCONCLUSIVE);
    }
}
