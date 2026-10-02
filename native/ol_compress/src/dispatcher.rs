//! The `Dispatcher` pick/compress/decompress surface.

use crate::error::CompressError;
use std::cell::RefCell;
use std::io::{Cursor, Read};

thread_local! {
    // One reusable zstd context per thread and level. `encode_all` built and
    // freed a full context (~1 MiB of match tables) for EVERY call: on 64 KiB
    // chunks that was ~40% of the codec time (ONE Memory, KITTI LiDAR: 111
    // MiB/s per 64 KiB call vs 188 MiB/s per 1 MiB call, same bytes, same
    // level). Contexts carry parameters only -- each call is one independent,
    // complete frame, so reuse cannot leak history between payloads.
    static ZSTD_ENCODERS: RefCell<[Option<zstd::bulk::Compressor<'static>>; 2]> =
        const { RefCell::new([None, None]) };
    static ZSTD_DECODER: RefCell<Option<zstd::bulk::Decompressor<'static>>> =
        const { RefCell::new(None) };
}

fn zstd_encode(bytes: &[u8], slot: usize, level: i32) -> Result<Vec<u8>, CompressError> {
    ZSTD_ENCODERS.with(|cell| {
        let mut encoders = cell.borrow_mut();
        let encoder = match &mut encoders[slot] {
            Some(encoder) => encoder,
            empty => empty.insert(zstd::bulk::Compressor::new(level)?),
        };
        // Frames now declare their content size, which lets `decompress`
        // reject an oversized frame before decoding and size its buffer once.
        Ok(encoder.compress(bytes)?)
    })
}

/// One-shot decode for a single frame that declares its size; `None` means
/// "not this shape" (no declared size, or several concatenated frames) and
/// the caller takes the streaming path.
fn zstd_decode_declared(body: &[u8], max: usize) -> Result<Option<Vec<u8>>, CompressError> {
    let Ok(Some(declared)) = zstd::zstd_safe::get_frame_content_size(body) else {
        return Ok(None);
    };
    let declared = usize::try_from(declared).unwrap_or(usize::MAX);
    // The bomb check happens on the header, before any decoding or allocation.
    ensure_output_bound(declared, max)?;
    if zstd::zstd_safe::find_frame_compressed_size(body) != Ok(body.len()) {
        return Ok(None);
    }
    ZSTD_DECODER.with(|cell| {
        let mut decoder = cell.borrow_mut();
        let decoder = match &mut *decoder {
            Some(decoder) => decoder,
            empty => {
                let mut fresh = zstd::bulk::Decompressor::new()?;
                fresh.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(
                    ZSTD_MAX_WINDOW_LOG,
                ))?;
                empty.insert(fresh)
            }
        };
        let out = decoder.decompress(body, declared)?;
        if out.len() != declared {
            return Err(CompressError::Zstd(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "zstd frame produced fewer bytes than it declared",
            )));
        }
        Ok(Some(out))
    })
}

/// Absolute per-call plaintext ceiling.
///
/// One Link transfers are chunked well below this limit (normally 256 KiB to
/// 4 MiB).  Keeping a process-wide ceiling as well as the caller-provided
/// `max_size` means an accidentally unbounded FFI caller cannot turn a small
/// hostile frame into an allocation bomb.
pub const MAX_DECOMPRESSED_BYTES: usize = 64 * 1024 * 1024;

/// Maximum tag-prefixed compressed payload accepted by the decoder.
///
/// The extra MiB covers the worst-case expansion of the supported codecs for
/// a [`MAX_DECOMPRESSED_BYTES`] incompressible input while still bounding CPU
/// spent consuming attacker-controlled compressed bytes.
pub const MAX_COMPRESSED_PAYLOAD_BYTES: usize = MAX_DECOMPRESSED_BYTES + 1024 * 1024;

// 2^26 == MAX_DECOMPRESSED_BYTES.  This prevents a zstd frame header from
// requesting an enormous history window before producing any output.
const ZSTD_MAX_WINDOW_LOG: u32 = 26;

/// Codecs supported by the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// No compression. Wire payload == input bytes (plus 1-byte tag).
    None,
    /// LZ4 block format (fast, ~3 GiB/s decode, ~1.5x ratio).
    Lz4,
    /// zstd level 3 (balanced — ~500 MiB/s, ~2-3x ratio).
    ZstdBalanced,
    /// zstd level 9 (slower, ~1.1x better ratio — for background).
    ZstdAggressive,
}

impl Algorithm {
    /// One-byte tag prepended to compressed output.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Lz4 => 1,
            Self::ZstdBalanced => 2,
            Self::ZstdAggressive => 3,
        }
    }

    /// Parse a tag byte back to an algorithm.
    pub fn from_tag(tag: u8) -> Result<Self, CompressError> {
        match tag {
            0 => Ok(Self::None),
            1 => Ok(Self::Lz4),
            2 => Ok(Self::ZstdBalanced),
            3 => Ok(Self::ZstdAggressive),
            _ => Err(CompressError::UnknownTag { tag }),
        }
    }
}

/// The event kind hint the dispatcher uses to pick a codec.
///
/// Same vocabulary as `ol_decide::EventKind` but defined locally so
/// this crate stays decoupled from the decide trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// Chat / text message — short, often emoji-heavy, low entropy.
    Msg,
    /// File transfer chunk — high entropy after the codec, anyway.
    File,
    /// CRDT sync / acknowledgement — small, repeating-structure JSON.
    Sync,
    /// Heartbeat / keepalive — tiny payloads.
    Heartbeat,
    /// Background sync / bulk index — speed less critical than ratio.
    Background,
}

/// Hint from the caller that the payload is already compressed (by
/// the application layer or the file format itself). When true, the
/// dispatcher returns [`Algorithm::None`] regardless of size — there's
/// nothing to be gained from a second pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreCompressed {
    /// Payload is already at high entropy (zip / mp4 / jpg etc).
    Yes,
    /// Plain bytes; compression may help.
    No,
}

/// The dispatcher. Stateless; one instance for the whole daemon.
#[derive(Debug, Default, Clone, Copy)]
pub struct Dispatcher;

impl Dispatcher {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Pick the algorithm appropriate for this `(kind, size, hint)`.
    ///
    /// Returns [`Algorithm::None`] for anything that won't compress
    /// well (tiny / already-compressed). Returns lz4 for fast sync
    /// paths and zstd for bulk transfer.
    #[must_use]
    pub fn pick(&self, kind: EventKind, size: usize, precompressed: PreCompressed) -> Algorithm {
        if precompressed == PreCompressed::Yes {
            return Algorithm::None;
        }
        match kind {
            EventKind::Msg => {
                if size < 4_096 {
                    Algorithm::None
                } else {
                    // A long message (paste / quote) is worth compressing.
                    Algorithm::Lz4
                }
            }
            EventKind::Heartbeat => Algorithm::None,
            EventKind::Sync => {
                if size < 8_192 {
                    Algorithm::Lz4
                } else {
                    Algorithm::ZstdBalanced
                }
            }
            EventKind::File => {
                if size < 1_048_576 {
                    Algorithm::Lz4
                } else {
                    Algorithm::ZstdBalanced
                }
            }
            EventKind::Background => Algorithm::ZstdAggressive,
        }
    }

    /// Compress `bytes` using `algo`. The output is tag-prefixed so
    /// `decompress` can route it without out-of-band metadata.
    ///
    /// # Errors
    /// zstd I/O errors propagate as [`CompressError::Zstd`].  Inputs above
    /// [`MAX_DECOMPRESSED_BYTES`] are rejected before codec work begins.
    pub fn compress(&self, algo: Algorithm, bytes: &[u8]) -> Result<Vec<u8>, CompressError> {
        if bytes.len() > MAX_DECOMPRESSED_BYTES {
            return Err(CompressError::InputTooLarge {
                actual: bytes.len(),
                max: MAX_DECOMPRESSED_BYTES,
            });
        }
        let mut out = Vec::with_capacity(bytes.len() + 8);
        out.push(algo.tag());
        match algo {
            Algorithm::None => {
                out.extend_from_slice(bytes);
            }
            Algorithm::Lz4 => {
                let payload = lz4_flex::block::compress_prepend_size(bytes);
                out.extend_from_slice(&payload);
            }
            Algorithm::ZstdBalanced => {
                out.extend_from_slice(&zstd_encode(bytes, 0, 3)?);
            }
            Algorithm::ZstdAggressive => {
                out.extend_from_slice(&zstd_encode(bytes, 1, 9)?);
            }
        }
        Ok(out)
    }

    /// Decompress a tagged payload. `max_size` is a defensive cap on
    /// the decompressed length — protects against decompression-bomb
    /// inputs (a 1 MiB compressed payload that expands to 1 GiB).
    ///
    /// # Errors
    /// Returns [`CompressError::UnknownTag`] for unrecognized tags,
    /// [`CompressError::PayloadTooShort`] for empty inputs, decoder
    /// errors for malformed payloads, and
    /// [`CompressError::OutputTooLarge`] if the output exceeds `max_size`.
    pub fn decompress(&self, payload: &[u8], max_size: usize) -> Result<Vec<u8>, CompressError> {
        if payload.is_empty() {
            return Err(CompressError::PayloadTooShort { len: 0 });
        }
        if payload.len() > MAX_COMPRESSED_PAYLOAD_BYTES {
            return Err(CompressError::PayloadTooLarge {
                actual: payload.len(),
                max: MAX_COMPRESSED_PAYLOAD_BYTES,
            });
        }
        let algo = Algorithm::from_tag(payload[0])?;
        let body = &payload[1..];
        let effective_max = max_size.min(MAX_DECOMPRESSED_BYTES);

        match algo {
            Algorithm::None => {
                ensure_output_bound(body.len(), effective_max)?;
                Ok(body.to_vec())
            }
            Algorithm::Lz4 => {
                // lz4_flex's convenience decoder allocates the four-byte
                // declared size immediately.  Inspect it before calling the
                // decoder so a forged u32 length cannot force a huge reserve.
                let (declared, _) = lz4_flex::block::uncompressed_size(body)?;
                ensure_output_bound(declared, effective_max)?;
                let out = lz4_flex::block::decompress_size_prepended(body)?;
                // Defense in depth if codec behavior ever changes.
                ensure_output_bound(out.len(), effective_max)?;
                Ok(out)
            }
            Algorithm::ZstdBalanced | Algorithm::ZstdAggressive => {
                if let Some(out) = zstd_decode_declared(body, effective_max)? {
                    return Ok(out);
                }
                // Frames without a declared size (written before contexts were
                // reused) or concatenated frames: bounded streaming decode.
                let mut decoder = zstd::stream::read::Decoder::new(Cursor::new(body))?;
                decoder.window_log_max(ZSTD_MAX_WINDOW_LOG)?;

                // Read at most one byte beyond the cap.  Unlike decode_all,
                // this bounds both allocation and decompression work even for
                // frames with unknown content size or concatenated frames.
                let read_limit = effective_max.saturating_add(1) as u64;
                let mut bounded = decoder.take(read_limit);
                let mut out = Vec::with_capacity(effective_max.min(64 * 1024));
                bounded.read_to_end(&mut out)?;
                ensure_output_bound(out.len(), effective_max)?;
                Ok(out)
            }
        }
    }
}

fn ensure_output_bound(actual: usize, max: usize) -> Result<(), CompressError> {
    if actual > max {
        return Err(CompressError::OutputTooLarge {
            decompressed: actual,
            max,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatcher() -> Dispatcher {
        Dispatcher::new()
    }

    // ───── pick() — codec selection ──────────────────────────────────

    #[test]
    fn pick_msg_small_returns_none() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::Msg, 200, PreCompressed::No),
            Algorithm::None
        );
    }

    #[test]
    fn pick_msg_large_returns_lz4() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::Msg, 5_000, PreCompressed::No),
            Algorithm::Lz4
        );
    }

    #[test]
    fn pick_heartbeat_always_none() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::Heartbeat, 64, PreCompressed::No),
            Algorithm::None
        );
        assert_eq!(
            d.pick(EventKind::Heartbeat, 8_000, PreCompressed::No),
            Algorithm::None
        );
    }

    #[test]
    fn pick_sync_small_lz4_large_zstd() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::Sync, 200, PreCompressed::No),
            Algorithm::Lz4
        );
        assert_eq!(
            d.pick(EventKind::Sync, 50_000, PreCompressed::No),
            Algorithm::ZstdBalanced
        );
    }

    #[test]
    fn pick_file_small_lz4_large_zstd() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::File, 100_000, PreCompressed::No),
            Algorithm::Lz4
        );
        assert_eq!(
            d.pick(EventKind::File, 5_000_000, PreCompressed::No),
            Algorithm::ZstdBalanced
        );
    }

    #[test]
    fn pick_background_always_aggressive() {
        let d = dispatcher();
        assert_eq!(
            d.pick(EventKind::Background, 100, PreCompressed::No),
            Algorithm::ZstdAggressive
        );
        assert_eq!(
            d.pick(EventKind::Background, 5_000_000, PreCompressed::No),
            Algorithm::ZstdAggressive
        );
    }

    #[test]
    fn pick_precompressed_always_none() {
        let d = dispatcher();
        for kind in [
            EventKind::Msg,
            EventKind::File,
            EventKind::Sync,
            EventKind::Heartbeat,
            EventKind::Background,
        ] {
            assert_eq!(d.pick(kind, 5_000_000, PreCompressed::Yes), Algorithm::None);
        }
    }

    // ───── compress / decompress round-trip ──────────────────────────

    fn round_trip(algo: Algorithm, input: &[u8]) -> Vec<u8> {
        let d = dispatcher();
        let compressed = d.compress(algo, input).unwrap();
        // Tag byte must match.
        assert_eq!(compressed[0], algo.tag());
        d.decompress(&compressed, usize::MAX).unwrap()
    }

    #[test]
    fn round_trip_none() {
        let input = b"hello world";
        assert_eq!(round_trip(Algorithm::None, input), input);
    }

    #[test]
    fn round_trip_lz4() {
        let input = b"hello hello hello hello hello hello hello hello world";
        assert_eq!(round_trip(Algorithm::Lz4, input), input);
    }

    #[test]
    fn round_trip_zstd_balanced() {
        let input = vec![42u8; 4096];
        assert_eq!(round_trip(Algorithm::ZstdBalanced, &input), input);
    }

    #[test]
    fn round_trip_zstd_aggressive() {
        let input = vec![42u8; 16_384];
        assert_eq!(round_trip(Algorithm::ZstdAggressive, &input), input);
    }

    #[test]
    fn round_trip_random_payload() {
        // A non-degenerate payload (no easy run-length advantage).
        let input: Vec<u8> = (0..1024u32).flat_map(u32::to_le_bytes).collect();
        for algo in [
            Algorithm::None,
            Algorithm::Lz4,
            Algorithm::ZstdBalanced,
            Algorithm::ZstdAggressive,
        ] {
            assert_eq!(round_trip(algo, &input), input, "{algo:?}");
        }
    }

    #[test]
    fn round_trip_empty_payload() {
        for algo in [
            Algorithm::None,
            Algorithm::Lz4,
            Algorithm::ZstdBalanced,
            Algorithm::ZstdAggressive,
        ] {
            assert_eq!(round_trip(algo, b""), b"", "{algo:?}");
        }
    }

    // ───── decompress validation ─────────────────────────────────────

    #[test]
    fn decompress_empty_rejected() {
        let d = dispatcher();
        assert!(matches!(
            d.decompress(b"", 1024),
            Err(CompressError::PayloadTooShort { len: 0 })
        ));
    }

    #[test]
    fn decompress_unknown_tag_rejected() {
        let d = dispatcher();
        let r = d.decompress(&[99u8, 0, 0, 0], 1024);
        assert!(matches!(r, Err(CompressError::UnknownTag { tag: 99 })));
    }

    #[test]
    fn decompress_caps_oversize_output() {
        let d = dispatcher();
        // Big repeating payload → zstd compresses tiny.
        let input = vec![7u8; 100_000];
        let compressed = d.compress(Algorithm::ZstdBalanced, &input).unwrap();
        let r = d.decompress(&compressed, 50_000);
        assert!(matches!(
            r,
            Err(CompressError::OutputTooLarge {
                decompressed,
                max: 50_000
            }) if decompressed > 50_000
        ));
    }

    #[test]
    fn lz4_declared_size_bomb_is_rejected_before_allocation() {
        let d = dispatcher();
        let mut payload = vec![Algorithm::Lz4.tag()];
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            d.decompress(&payload, 1024),
            Err(CompressError::OutputTooLarge {
                decompressed,
                max: 1024
            }) if decompressed == u32::MAX as usize
        ));
    }

    #[test]
    fn none_payload_checks_bound_before_copying() {
        let d = dispatcher();
        let payload = vec![Algorithm::None.tag(); 4097];
        assert!(matches!(
            d.decompress(&payload, 4095),
            Err(CompressError::OutputTooLarge {
                decompressed: 4096,
                max: 4095
            })
        ));
    }

    #[test]
    fn process_wide_output_ceiling_applies_to_unbounded_caller() {
        let d = dispatcher();
        let mut payload = vec![Algorithm::Lz4.tag()];
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            d.decompress(&payload, usize::MAX),
            Err(CompressError::OutputTooLarge {
                decompressed,
                max: MAX_DECOMPRESSED_BYTES
            }) if decompressed == u32::MAX as usize
        ));
    }

    // ───── Algorithm tag round-trip ─────────────────────────────────

    #[test]
    fn algorithm_tag_round_trip() {
        for algo in [
            Algorithm::None,
            Algorithm::Lz4,
            Algorithm::ZstdBalanced,
            Algorithm::ZstdAggressive,
        ] {
            assert_eq!(Algorithm::from_tag(algo.tag()).unwrap(), algo);
        }
    }

    // ───── reused zstd contexts ─────────────────────────────────────

    fn lidar_like(n: usize, seed: u32) -> Vec<u8> {
        // Float-ish structured bytes: compressible, but not trivially.
        (0..n as u32)
            .flat_map(|i| {
                (i.wrapping_mul(2_654_435_761) ^ seed)
                    .rotate_left(i % 13)
                    .to_le_bytes()
            })
            .collect()
    }

    #[test]
    fn frames_written_before_context_reuse_still_decode() {
        // `encode_all` frames carry no content size: they must take the
        // streaming path and decode exactly as before (stored data compat).
        let d = dispatcher();
        let input = lidar_like(50_000, 7);
        for (algo, level) in [(Algorithm::ZstdBalanced, 3), (Algorithm::ZstdAggressive, 9)] {
            let mut legacy = vec![algo.tag()];
            legacy.extend_from_slice(&zstd::stream::encode_all(&input[..], level).unwrap());
            assert_eq!(
                zstd::zstd_safe::get_frame_content_size(&legacy[1..]).unwrap(),
                None,
                "the legacy frame must lack a declared size for this test to bite"
            );
            assert_eq!(d.decompress(&legacy, input.len()).unwrap(), input);
        }
    }

    #[test]
    fn new_frames_declare_their_size_and_round_trip() {
        let d = dispatcher();
        for n in [0, 1, 4096, 65_536, 300_001] {
            let input = lidar_like(n / 4 + 1, 3);
            let c = d.compress(Algorithm::ZstdBalanced, &input).unwrap();
            assert_eq!(
                zstd::zstd_safe::get_frame_content_size(&c[1..]).unwrap(),
                Some(input.len() as u64)
            );
            assert_eq!(d.decompress(&c, input.len()).unwrap(), input);
        }
    }

    #[test]
    fn declared_size_bomb_is_rejected_from_the_header() {
        // The one-shot path reports the DECLARED size (the streaming path can
        // only report max+1): proof the check ran before any decoding.
        let d = dispatcher();
        let c = d
            .compress(Algorithm::ZstdBalanced, &vec![7u8; 100_000])
            .unwrap();
        assert!(matches!(
            d.decompress(&c, 1_000),
            Err(CompressError::OutputTooLarge {
                decompressed: 100_000,
                max: 1_000
            })
        ));
    }

    #[test]
    fn concatenated_frames_still_decode_through_the_streaming_path() {
        let d = dispatcher();
        let a = lidar_like(1_000, 1);
        let b = lidar_like(2_000, 2);
        let mut payload = d.compress(Algorithm::ZstdBalanced, &a).unwrap();
        payload.extend_from_slice(&d.compress(Algorithm::ZstdBalanced, &b).unwrap()[1..]);
        let mut both = a.clone();
        both.extend_from_slice(&b);
        assert_eq!(d.decompress(&payload, both.len()).unwrap(), both);
        assert!(d.decompress(&payload, both.len() - 1).is_err());
    }

    #[test]
    fn reused_context_is_deterministic_and_leaks_nothing_between_calls() {
        let d = dispatcher();
        let a = lidar_like(20_000, 11);
        let b = lidar_like(20_000, 12);
        let first = d.compress(Algorithm::ZstdBalanced, &a).unwrap();
        let _ = d.compress(Algorithm::ZstdBalanced, &b).unwrap();
        let _ = d.compress(Algorithm::ZstdAggressive, &b).unwrap();
        let again = d.compress(Algorithm::ZstdBalanced, &a).unwrap();
        assert_eq!(
            first, again,
            "a frame must not depend on what the context saw before"
        );
        let fresh = zstd::bulk::compress(&a, 3).unwrap();
        assert_eq!(
            &first[1..],
            &fresh[..],
            "reuse must equal a fresh one-shot context"
        );
    }

    #[test]
    fn contexts_are_per_thread_and_correct_under_concurrency() {
        let handles: Vec<_> = (0..8u32)
            .map(|t| {
                std::thread::spawn(move || {
                    let d = Dispatcher::new();
                    for i in 0..50u32 {
                        let input = lidar_like(4_096 + (i as usize) * 97, t * 1_000 + i);
                        let algo = if i % 2 == 0 {
                            Algorithm::ZstdBalanced
                        } else {
                            Algorithm::ZstdAggressive
                        };
                        let c = d.compress(algo, &input).unwrap();
                        assert_eq!(d.decompress(&c, input.len()).unwrap(), input);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
}
