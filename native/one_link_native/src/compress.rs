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
    Ok(())
}
