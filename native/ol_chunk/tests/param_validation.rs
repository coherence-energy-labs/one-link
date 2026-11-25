//! `CdcParams::validate` accepts exactly the profiles the `FastCDC` v2020
//! kernel accepts that also satisfy `min < avg < max`, and every public scan
//! entry point refuses an invalid profile with an error.
//!
//! Before this, validation only required non-zero, ordered sizes with
//! `max <= 16 MiB`. Profiles such as `(1, 2, 4)`, `(63, 256, 1024)` and
//! `(1 MiB + 1, 2 MiB, 4 MiB)` passed it and then hit the kernel's `assert!`s
//! (a process abort under the release profile's `panic = "abort"`), or, in the
//! parallel kernel used by the file scanner, a zero-length cut that looped
//! until a boundary vector asked for 27 GB.

use std::io::{self, Cursor};

use fastcdc::v2020::{
    FastCDC, AVERAGE_MAX, AVERAGE_MIN, MAXIMUM_MAX, MAXIMUM_MIN, MINIMUM_MAX, MINIMUM_MIN,
};
use ol_chunk::stream::{scan_format_aware_seekable, scan_stream, StreamScanError};
use ol_chunk::{
    pcdc, scan_format_aware, scan_to_vec_parallel_with_params, Boundary, CdcParams, ChunkError,
    ChunkScanner, ContainerFormat,
};

const MIB: u32 = 1 << 20;

fn p(min_size: u32, avg_size: u32, max_size: u32) -> CdcParams {
    CdcParams {
        min_size,
        avg_size,
        max_size,
    }
}

/// Whether the kernel's own constructor accepts the sizes (it panics if not).
fn kernel_accepts(params: CdcParams) -> bool {
    std::panic::catch_unwind(|| {
        let _ = FastCDC::new(&[], params.min_size, params.avg_size, params.max_size);
    })
    .is_ok()
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[3]
        })
        .collect()
}

fn formats() -> [Option<ContainerFormat>; 6] {
    [
        None,
        Some(ContainerFormat::Zip),
        Some(ContainerFormat::Mp4),
        Some(ContainerFormat::Wav),
        Some(ContainerFormat::H264AnnexB),
        Some(ContainerFormat::Mcap),
    ]
}

fn assert_out_of_range(params: CdcParams, field: &str, value: u32) {
    match params.validate() {
        Err(ChunkError::SizeOutOfRange {
            field: f,
            value: v,
            min,
            max,
        }) => {
            assert_eq!((f, v), (field, value), "{params:?}");
            let range = match field {
                "min_size" => CdcParams::MIN_SIZE_RANGE,
                "avg_size" => CdcParams::AVG_SIZE_RANGE,
                _ => CdcParams::MAX_SIZE_RANGE,
            };
            assert_eq!(min..=max, range, "{params:?}");
        }
        other => panic!("{params:?}: expected {field} = {value} out of range, got {other:?}"),
    }
}

#[test]
fn the_accepted_ranges_are_the_kernels_exported_constants() {
    assert_eq!(CdcParams::MIN_SIZE_RANGE, MINIMUM_MIN..=MINIMUM_MAX);
    assert_eq!(CdcParams::AVG_SIZE_RANGE, AVERAGE_MIN..=AVERAGE_MAX);
    assert_eq!(CdcParams::MAX_SIZE_RANGE, MAXIMUM_MIN..=MAXIMUM_MAX);
    // fastcdc 3.2.1's values. A dependency bump that moves them fails here,
    // so the change is reviewed rather than inherited silently.
    assert_eq!(
        [
            MINIMUM_MIN,
            MINIMUM_MAX,
            AVERAGE_MIN,
            AVERAGE_MAX,
            MAXIMUM_MIN,
            MAXIMUM_MAX
        ],
        [64, MIB, 256, 4 * MIB, 1024, 16 * MIB]
    );
    assert!(CdcParams::default().validate().is_ok());
}

#[test]
fn each_kernel_limit_rejects_one_past_it_and_accepts_the_limit_itself() {
    // (rejected, field, value, accepted at the limit, accepted one inside)
    let cases = [
        (
            p(63, 256, 1024),
            "min_size",
            63,
            p(64, 256, 1024),
            p(65, 256, 1024),
        ),
        (
            p(MIB + 1, 2 * MIB, 4 * MIB),
            "min_size",
            MIB + 1,
            p(MIB, 2 * MIB, 4 * MIB),
            p(MIB - 1, 2 * MIB, 4 * MIB),
        ),
        (
            p(64, 255, 1024),
            "avg_size",
            255,
            p(64, 256, 1024),
            p(64, 257, 1024),
        ),
        (
            p(MIB, 4 * MIB + 1, 16 * MIB),
            "avg_size",
            4 * MIB + 1,
            p(MIB, 4 * MIB, 16 * MIB),
            p(MIB, 4 * MIB - 1, 16 * MIB),
        ),
        (
            p(64, 256, 1023),
            "max_size",
            1023,
            p(64, 256, 1024),
            p(64, 256, 1025),
        ),
        (
            p(MIB, 4 * MIB, 16 * MIB + 1),
            "max_size",
            16 * MIB + 1,
            p(MIB, 4 * MIB, 16 * MIB),
            p(MIB, 4 * MIB, 16 * MIB - 1),
        ),
    ];
    for (rejected, field, value, at_limit, inside) in cases {
        assert_out_of_range(rejected, field, value);
        assert!(
            !kernel_accepts(rejected),
            "{rejected:?}: the kernel must refuse it too"
        );
        for accepted in [at_limit, inside] {
            assert!(accepted.validate().is_ok(), "{accepted:?}");
            assert!(kernel_accepts(accepted), "{accepted:?}");
        }
    }
}

#[test]
fn the_witnessed_abort_and_loop_profiles_are_rejected() {
    assert_out_of_range(p(1, 2, 4), "min_size", 1);
    assert_out_of_range(p(63, 256, 1024), "min_size", 63);
    assert_out_of_range(p(MIB + 1, 2 * MIB, 4 * MIB), "min_size", MIB + 1);
    for witness in [p(1, 2, 4), p(63, 256, 1024), p(MIB + 1, 2 * MIB, 4 * MIB)] {
        assert!(!kernel_accepts(witness), "{witness:?}");
    }
    // The error text names the field, the value and the kernel's range.
    assert_eq!(
        p(63, 256, 1024).validate().unwrap_err().to_string(),
        "invalid CDC parameters: min_size = 63 is outside the FastCDC range 64..=1048576"
    );
}

#[test]
fn validate_agrees_with_the_kernel_constructor_on_every_probe_combination() {
    // Every limit, its neighbours, the witnessed values and the extremes,
    // tried in every field: 24^3 profiles against the library itself.
    let probes = [
        0,
        1,
        2,
        4,
        63,
        64,
        65,
        255,
        256,
        257,
        1023,
        1024,
        1025,
        MIB - 1,
        MIB,
        MIB + 1,
        2 * MIB,
        4 * MIB - 1,
        4 * MIB,
        4 * MIB + 1,
        16 * MIB - 1,
        16 * MIB,
        16 * MIB + 1,
        u32::MAX,
    ];
    let (mut accepted, mut kernel_refused, mut order_refused) = (0, 0, 0);
    for &min_size in &probes {
        for &avg_size in &probes {
            for &max_size in &probes {
                let params = p(min_size, avg_size, max_size);
                let ours = params.validate().is_ok();
                let kernel = kernel_accepts(params);
                let ordered = min_size < avg_size && avg_size < max_size;
                assert!(
                    !ours || kernel,
                    "{params:?} accepted but the kernel refuses it"
                );
                assert_eq!(ours, kernel && ordered, "{params:?}");
                accepted += usize::from(ours);
                kernel_refused += usize::from(!kernel);
                order_refused += usize::from(kernel && !ordered);
            }
        }
    }
    // The comparison exercised all three outcomes, so it can fail.
    assert!(accepted > 0 && kernel_refused > 0 && order_refused > 0);
}

#[test]
fn every_scan_entry_point_refuses_an_invalid_profile_with_an_error() {
    let invalid = [
        p(1, 2, 4),
        p(63, 256, 1024),
        p(MIB + 1, 2 * MIB, 4 * MIB),
        p(64, 255, 1024),
        p(64, 256, 1023),
        p(MIB, 4 * MIB + 1, 16 * MIB),
        p(MIB, 4 * MIB, 16 * MIB + 1),
        p(0, 0, 0),
        p(u32::MAX, u32::MAX, u32::MAX),
        p(4096, 1024, 8192), // in range, out of order
    ];
    // 100 bytes: the file whose scan asked for 27,380,416,512 bytes. 1 MiB + 1:
    // large enough for the parallel kernel path of the in-memory scanner.
    let small = noise(100, 1);
    let large = noise((1 << 20) + 1, 2);
    for bad in invalid {
        assert!(ChunkScanner::with_params(&small, bad).is_err(), "{bad:?}");
        for buf in [&small, &large] {
            assert!(
                scan_to_vec_parallel_with_params(buf, bad).is_err(),
                "{bad:?}"
            );
            assert!(pcdc::chunk_ranges(buf, bad).is_err(), "{bad:?}");
        }
        let err = scan_stream(Cursor::new(&small), small.len(), bad).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
        assert!(
            err.get_ref()
                .and_then(|inner| inner.downcast_ref::<ChunkError>())
                .is_some(),
            "{bad:?}: the ChunkError is kept as the io::Error's source"
        );
        for format in formats() {
            assert!(
                scan_format_aware(&small, format, bad).is_err(),
                "{bad:?} {format:?}"
            );
            assert!(
                matches!(
                    scan_format_aware_seekable(
                        &mut Cursor::new(&small),
                        small.len(),
                        format,
                        bad,
                        usize::MAX
                    ),
                    Err(StreamScanError::Params(_))
                ),
                "{bad:?} {format:?}"
            );
        }
    }
}

fn assert_tiles(bounds: &[Boundary], data: &[u8], params: CdcParams) {
    assert_eq!(bounds.first().map(|b| b.start), Some(0), "{params:?}");
    assert_eq!(bounds.last().map(|b| b.end), Some(data.len()), "{params:?}");
    for pair in bounds.windows(2) {
        assert_eq!(pair[0].end, pair[1].start, "{params:?}");
    }
    for b in bounds {
        assert!(
            b.start < b.end && b.end - b.start <= params.max_size as usize,
            "{params:?} {b:?}"
        );
    }
}

#[test]
fn every_scan_entry_point_chunks_at_the_extreme_accepted_profiles() {
    let profiles = [
        p(MINIMUM_MIN, AVERAGE_MIN, MAXIMUM_MIN), // smallest everything
        p(MINIMUM_MAX, AVERAGE_MAX, MAXIMUM_MAX), // largest everything
        p(MINIMUM_MIN, AVERAGE_MAX, MAXIMUM_MAX), // widest spread
        p(MAXIMUM_MIN - 2, MAXIMUM_MIN - 1, MAXIMUM_MIN), // tightest, smallest max
        p(AVERAGE_MIN - 1, AVERAGE_MIN, MAXIMUM_MIN), // odd minimum
        p(MINIMUM_MAX, MINIMUM_MAX + 1, MINIMUM_MAX + 2), // tightest, largest min
    ];
    // Over 1 MiB so the parallel kernel runs, with an odd tail; noise, and
    // the kernel's pathological all-zero input.
    let inputs = [noise((3 << 20) + 17, 3), vec![0u8; (3 << 20) + 17]];
    for params in profiles {
        assert!(params.validate().is_ok(), "{params:?}");
        for data in &inputs {
            let serial: Vec<Boundary> = ChunkScanner::with_params(data, params).unwrap().collect();
            assert_tiles(&serial, data, params);
            let ranges: Vec<(usize, usize)> = serial.iter().map(|b| (b.start, b.end)).collect();
            assert_eq!(
                pcdc::chunk_ranges(data, params).unwrap(),
                ranges,
                "{params:?}"
            );
            assert_eq!(
                scan_to_vec_parallel_with_params(data, params).unwrap(),
                serial,
                "{params:?}"
            );
            assert_eq!(
                scan_stream(Cursor::new(data), data.len(), params).unwrap(),
                serial,
                "{params:?}"
            );
            assert_eq!(
                scan_format_aware(data, None, params).unwrap().boundaries,
                serial,
                "{params:?}"
            );
            assert_eq!(
                scan_format_aware_seekable(
                    &mut Cursor::new(data),
                    data.len(),
                    None,
                    params,
                    usize::MAX
                )
                .unwrap()
                .boundaries,
                serial,
                "{params:?}"
            );
        }
    }
}
