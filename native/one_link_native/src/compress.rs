//! `one_link_native.compress` — Python binding for `ol_compress`.
//!
//! Surfaces the per-payload codec dispatcher. The daemon's chunk encoder
//! (daemon.py:~11500 per integration map) consumes `pick` to choose
//! between lz4 / zstd / none and `compress` + `decompress` for the
//! round-trip.

use crate::chunk::contiguous_buffer_snapshot;
use ol_compress::{Algorithm, CompressError, Dispatcher, EventKind, PreCompressed};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

/// Run a codec call with the interpreter detached, so N Python threads
/// compress or decompress on N cores (it held the GIL before: 8 threads ran at
/// 1.0x of one). ``bytes`` are borrowed zero-copy (immutable); any other
/// buffer is snapshotted first, because a second thread could mutate it.
fn detached<T: Send>(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    work: impl Fn(&[u8]) -> T + Send + Sync,
) -> PyResult<T> {
    if let Ok(bytes) = obj.cast::<PyBytes>() {
        let immutable = PyBackedBytes::from(bytes.to_owned());
        Ok(py.detach(move || work(&immutable)))
    } else {
        let owned = contiguous_buffer_snapshot(py, obj)?;
        Ok(py.detach(move || work(&owned)))
    }
}

/// Python-visible dispatcher. Stateless; one instance for the daemon.
#[pyclass(
    from_py_object,
    name = "Compressor",
    module = "one_link_native.compress"
)]
#[derive(Debug, Default, Clone)]
pub struct PyCompressor {
    inner: Dispatcher,
}

#[pymethods]
impl PyCompressor {
    #[new]
    fn new() -> Self {
        Self {
            inner: Dispatcher::new(),
        }
    }

    /// Pick a codec for (kind, size, precompressed).
    ///
    /// `kind` accepts: "msg" | "file" | "sync" | "heartbeat" | "background".
    /// `precompressed`: pass True for already-compressed payloads
    /// (zip/mp4/jpg/etc) so the dispatcher returns "none".
    ///
    /// Returns a string codec name:
    ///   "none" | "lz4" | "`zstd_balanced`" | "`zstd_aggressive`"
    #[pyo3(signature = (kind, size, precompressed = false))]
    fn pick(&self, kind: &str, size: usize, precompressed: bool) -> PyResult<&'static str> {
        let k = parse_event_kind(kind)?;
        let pc = if precompressed {
            PreCompressed::Yes
        } else {
            PreCompressed::No
        };
        Ok(algo_str(self.inner.pick(k, size, pc)))
    }

    /// Compress `bytes` using `algo` ("none" | "lz4" | "`zstd_balanced`"
    /// | "`zstd_aggressive`"). Returns the tag-prefixed compressed bytes.
    ///
    /// Releases the GIL while compressing.
    #[pyo3(signature = (algo, payload))]
    fn compress<'py>(
        &self,
        py: Python<'py>,
        algo: &str,
        payload: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let a = parse_algo(algo)?;
        let inner = self.inner;
        let out = detached(py, payload, move |bytes| inner.compress(a, bytes))?
            .map_err(|err| compress_err_to_py(&err))?;
        Ok(PyBytes::new(py, &out))
    }

    /// Decompress a tag-prefixed payload. `max_size` is a defensive
    /// upper bound on the decompressed length — protects against
    /// decompression-bomb payloads.
    ///
    /// Releases the GIL while decompressing.
    #[pyo3(signature = (payload, max_size))]
    fn decompress<'py>(
        &self,
        py: Python<'py>,
        payload: &Bound<'py, PyAny>,
        max_size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.inner;
        let out = detached(py, payload, move |bytes| inner.decompress(bytes, max_size))?
            .map_err(|err| compress_err_to_py(&err))?;
        Ok(PyBytes::new(py, &out))
    }

    fn __repr__(&self) -> &'static str {
        let _ = &self.inner;
        "Compressor()"
    }
}

fn parse_event_kind(s: &str) -> PyResult<EventKind> {
    match s.to_ascii_lowercase().as_str() {
        "msg" | "text" => Ok(EventKind::Msg),
        "file" | "file_chunk" | "file_offer" => Ok(EventKind::File),
        "sync" | "ack" => Ok(EventKind::Sync),
        "heartbeat" | "ping" | "pong" => Ok(EventKind::Heartbeat),
        "background" | "bg" => Ok(EventKind::Background),
        other => Err(PyValueError::new_err(format!(
            "unknown kind: {other:?} (expected msg|file|sync|heartbeat|background)"
        ))),
    }
}

fn parse_algo(s: &str) -> PyResult<Algorithm> {
    match s.to_ascii_lowercase().as_str() {
        "none" => Ok(Algorithm::None),
        "lz4" => Ok(Algorithm::Lz4),
        "zstd_balanced" | "zstd" => Ok(Algorithm::ZstdBalanced),
        "zstd_aggressive" | "zstd_max" => Ok(Algorithm::ZstdAggressive),
        other => Err(PyValueError::new_err(format!(
            "unknown algo: {other:?} (expected none|lz4|zstd_balanced|zstd_aggressive)"
        ))),
    }
}

fn algo_str(a: Algorithm) -> &'static str {
    match a {
        Algorithm::None => "none",
        Algorithm::Lz4 => "lz4",
        Algorithm::ZstdBalanced => "zstd_balanced",
        Algorithm::ZstdAggressive => "zstd_aggressive",
    }
}

fn compress_err_to_py(err: &CompressError) -> PyErr {
    PyValueError::new_err(err.to_string())
}

/// Register the `compress` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_compress::VERSION)?;
    m.add(
        "MAX_DECOMPRESSED_BYTES",
        ol_compress::MAX_DECOMPRESSED_BYTES,
    )?;
    m.add(
        "MAX_COMPRESSED_PAYLOAD_BYTES",
        ol_compress::MAX_COMPRESSED_PAYLOAD_BYTES,
    )?;
    m.add_class::<PyCompressor>()?;
    m.add_function(wrap_pyfunction!(onemem_sha256_many, m)?)?;
    m.add_function(wrap_pyfunction!(onemem_encode_many, m)?)?;
    m.add_function(wrap_pyfunction!(onemem_sha256_slices, m)?)?;
    m.add_function(wrap_pyfunction!(onemem_encode_slices, m)?)?;
    m.add_function(wrap_pyfunction!(onemem_decode_many, m)?)?;
    Ok(())
}

/// Decode and SHA-256-verify ONE Memory chunks in parallel, interpreter
/// detached. Entry ``i`` is the plaintext, or ``None`` when chunk ``i`` is not
/// this path's to serve (encrypted, zlib, malformed, or failing verification):
/// the caller's own decoder then handles it and owns the error semantics.
#[pyfunction]
fn onemem_decode_many<'py>(
    py: Python<'py>,
    encoded: &Bound<'py, PyAny>,
    digests: Vec<Vec<u8>>,
) -> PyResult<Vec<Option<Bound<'py, PyBytes>>>> {
    let owned = backed(encoded)?;
    if owned.len() != digests.len() {
        return Err(PyValueError::new_err("one digest per encoded chunk"));
    }
    let expected: Vec<[u8; 32]> = digests
        .into_iter()
        .map(|d| {
            <[u8; 32]>::try_from(d.as_slice())
                .map_err(|_| PyValueError::new_err("digests are 32-byte SHA-256 values"))
        })
        .collect::<PyResult<_>>()?;
    let plain = py.detach(move || {
        let refs: Vec<&[u8]> = owned.iter().map(|c| &c[..]).collect();
        ol_compress::onemem::decode_many(&refs, &expected)
    });
    Ok(plain
        .into_iter()
        .map(|p| p.map(|bytes| PyBytes::new(py, &bytes)))
        .collect())
}

/// Borrow ``source`` (must be ``bytes``: immutable, so safe to read detached)
/// and validate every ``(start, end)`` range against it.
fn source_and_bounds(
    source: &Bound<'_, PyAny>,
    bounds: &[(usize, usize)],
) -> PyResult<PyBackedBytes> {
    let bytes = source
        .cast::<PyBytes>()
        .map_err(|_| PyValueError::new_err("ONE Memory slice batches borrow a bytes source"))?;
    let backed = PyBackedBytes::from(bytes.to_owned());
    if let Some(&(s, e)) = bounds.iter().find(|&&(s, e)| s > e || e > backed.len()) {
        return Err(PyValueError::new_err(format!(
            "slice ({s}, {e}) is outside a source of {} bytes",
            backed.len()
        )));
    }
    Ok(backed)
}

/// SHA-256 of ``source[start:end]`` for each bound, zero-copy and in parallel.
///
/// ONE Memory measured copying each chunk out of its blob at 0.5 ms/MiB --
/// a third of ingest -- before any hashing began.
#[pyfunction]
fn onemem_sha256_slices<'py>(
    py: Python<'py>,
    source: &Bound<'py, PyAny>,
    bounds: Vec<(usize, usize)>,
) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    let backed = source_and_bounds(source, &bounds)?;
    let digests = py.detach(move || {
        let refs: Vec<&[u8]> = bounds.iter().map(|&(s, e)| &backed[s..e]).collect();
        ol_compress::onemem::sha256_many(&refs)
    });
    Ok(digests.iter().map(|d| PyBytes::new(py, d)).collect())
}

/// ``onemem_encode_many`` over ``source[start:end]`` slices, zero-copy.
#[pyfunction]
#[pyo3(signature = (source, bounds, algorithm, precompressed = false, compress = true))]
fn onemem_encode_slices<'py>(
    py: Python<'py>,
    source: &Bound<'py, PyAny>,
    bounds: Vec<(usize, usize)>,
    algorithm: &str,
    precompressed: bool,
    compress: bool,
) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    let mode = ol_compress::onemem::Mode::parse(algorithm).ok_or_else(|| {
        PyValueError::new_err(format!("algorithm {algorithm:?} is not on the native path"))
    })?;
    let backed = source_and_bounds(source, &bounds)?;
    let encoded = py.detach(move || {
        let refs: Vec<&[u8]> = bounds.iter().map(|&(s, e)| &backed[s..e]).collect();
        ol_compress::onemem::encode_many(&refs, mode, precompressed, compress)
    });
    encoded
        .into_iter()
        .map(|r| {
            r.map(|bytes| PyBytes::new(py, &bytes))
                .map_err(|err| compress_err_to_py(&err))
        })
        .collect()
}

fn backed(chunks: &Bound<'_, PyAny>) -> PyResult<Vec<PyBackedBytes>> {
    chunks
        .try_iter()?
        .map(|item| {
            let item = item?;
            item.cast::<PyBytes>()
                .map(|b| PyBackedBytes::from(b.to_owned()))
                .map_err(|_| PyValueError::new_err("ONE Memory batches take bytes chunks"))
        })
        .collect()
}

/// SHA-256 of every chunk, in parallel with the interpreter detached.
///
/// ONE Memory's ingest identities: one call per window of chunks.
#[pyfunction]
fn onemem_sha256_many<'py>(
    py: Python<'py>,
    chunks: &Bound<'py, PyAny>,
) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    let owned = backed(chunks)?;
    let digests = py.detach(move || {
        let refs: Vec<&[u8]> = owned.iter().map(|c| &c[..]).collect();
        ol_compress::onemem::sha256_many(&refs)
    });
    Ok(digests.iter().map(|d| PyBytes::new(py, d)).collect())
}

/// Encode chunks in ONE Memory's V2 format (unencrypted), in parallel with the
/// interpreter detached; byte-identical to ``one_storage.codec.encode_chunk``.
///
/// ``algorithm``: one of `auto`, `auto_fast`, `none`, `lz4`, `zstd_balanced`,
/// `zstd_aggressive`.
#[pyfunction]
#[pyo3(signature = (chunks, algorithm, precompressed = false, compress = true))]
fn onemem_encode_many<'py>(
    py: Python<'py>,
    chunks: &Bound<'py, PyAny>,
    algorithm: &str,
    precompressed: bool,
    compress: bool,
) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    let mode = ol_compress::onemem::Mode::parse(algorithm).ok_or_else(|| {
        PyValueError::new_err(format!("algorithm {algorithm:?} is not on the native path"))
    })?;
    let owned = backed(chunks)?;
    let encoded = py.detach(move || {
        let refs: Vec<&[u8]> = owned.iter().map(|c| &c[..]).collect();
        ol_compress::onemem::encode_many(&refs, mode, precompressed, compress)
    });
    encoded
        .into_iter()
        .map(|r| {
            r.map(|bytes| PyBytes::new(py, &bytes))
                .map_err(|err| compress_err_to_py(&err))
        })
        .collect()
}
