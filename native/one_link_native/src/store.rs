//! `one_link_native.store` — Python binding for `ol_chunk_store`.
//!
//! Surfaces the integrating chunk-store layer: write+manifest+flush,
//! has/locate/read, replay stats. The Python daemon swaps in this
//! module wholesale to replace the legacy `blobstore.py`.

use std::path::PathBuf;

use ol_chunk_store::{
    ChunkAddressKind, ChunkAeadKind, ChunkLocation, ChunkRecord, ChunkRecordKind, ChunkStore,
    ManifestRecord, ManifestRecordKind, StripeDescriptor, StripeRole,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::chunk_store_error_to_pyerr;

fn parse_address_kind(s: &str) -> PyResult<ChunkAddressKind> {
    match s {
        "raw" => Ok(ChunkAddressKind::Raw),
        "convergent" => Ok(ChunkAddressKind::Convergent),
        other => Err(PyValueError::new_err(format!(
            "unknown address_kind '{other}'; expected 'raw' or 'convergent'"
        ))),
    }
}

fn parse_aead_kind(s: &str) -> PyResult<ChunkAeadKind> {
    match s {
        "aes" => Ok(ChunkAeadKind::AesGcm256),
        "chacha" => Ok(ChunkAeadKind::ChaCha20Poly1305),
        other => Err(PyValueError::new_err(format!(
            "unknown aead_kind '{other}'; expected 'aes' or 'chacha'"
        ))),
    }
}

fn parse_record_kind(s: &str) -> PyResult<ChunkRecordKind> {
    match s {
        "blob" => Ok(ChunkRecordKind::ChunkBlob),
        "parity" => Ok(ChunkRecordKind::StripeParity),
        "tombstone" => Ok(ChunkRecordKind::TombstoneRef),
        other => Err(PyValueError::new_err(format!(
            "unknown chunk record kind '{other}'; expected 'blob', 'parity', or 'tombstone'"
        ))),
    }
}

fn parse_manifest_kind(s: &str) -> PyResult<ManifestRecordKind> {
    match s {
        "manifest_version" | "manifest" => Ok(ManifestRecordKind::ManifestVersion),
        "capability_grant" | "grant" => Ok(ManifestRecordKind::CapabilityGrant),
        "capability_revoke" | "revoke" => Ok(ManifestRecordKind::CapabilityRevoke),
        "merkle_revocation" => Ok(ManifestRecordKind::MerkleRevocationLogEntry),
        "share_link" => Ok(ManifestRecordKind::ShareLink),
        "sentinel" => Ok(ManifestRecordKind::Sentinel),
        other => Err(PyValueError::new_err(format!(
            "unknown manifest record kind '{other}'"
        ))),
    }
}

/// The error for an id of the wrong length. Out of line, so that the checks
/// below are a length test and a copy that the compiler folds into each
/// caller.
#[cold]
#[inline(never)]
fn wrong_length(what: &str, want: usize, got: usize) -> PyErr {
    PyValueError::new_err(format!("{what} must be {want} bytes, got {got}"))
}

// The three checks run on every call that names a chunk. Inlined, they cost a
// compare; as calls of their own (which is how the optimizer left them once
// unwinding made each one carry a cleanup path for its error) the id was
// written to memory by the callee and read straight back by the caller, and
// a lookup took about a tenth longer.
#[inline]
fn check_chunk_id(b: &[u8]) -> PyResult<[u8; 32]> {
    b.try_into()
        .map_err(|_| wrong_length("chunk_id", 32, b.len()))
}

#[inline]
fn check_ratchet_id(b: &[u8]) -> PyResult<[u8; 16]> {
    b.try_into()
        .map_err(|_| wrong_length("ratchet_key_id", 16, b.len()))
}

#[inline]
fn check_actor_id(b: &[u8]) -> PyResult<[u8; 32]> {
    b.try_into()
        .map_err(|_| wrong_length("actor_id", 32, b.len()))
}

/// Python view of a chunk record (everything the daemon needs).
#[pyclass(
    from_py_object,
    name = "ReadChunk",
    module = "one_link_native.store",
    frozen
)]
#[derive(Debug, Clone)]
pub struct PyReadChunk {
    // One of a fixed set of names: borrowed, so that building this view
    // allocates nothing for them.
    #[pyo3(get)]
    kind: &'static str,
    #[pyo3(get)]
    address_kind: &'static str,
    #[pyo3(get)]
    aead_kind: &'static str,
    #[pyo3(get)]
    compressed: bool,
    #[pyo3(get)]
    format_aware: bool,
    #[pyo3(get)]
    length_plaintext: u32,
    chunk_id: [u8; 32],
    ratchet_key_id: [u8; 16],
    ciphertext: Vec<u8>,
    stripe: PyStripe,
}

#[pymethods]
impl PyReadChunk {
    #[getter]
    fn chunk_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.chunk_id)
    }
    #[getter]
    fn ratchet_key_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.ratchet_key_id)
    }
    #[getter]
    fn ciphertext<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.ciphertext)
    }
    #[getter]
    fn stripe(&self) -> PyStripe {
        self.stripe.clone()
    }
}

impl PyReadChunk {
    fn from_rust(r: ChunkRecord) -> Self {
        let kind = match r.kind {
            ChunkRecordKind::ChunkBlob => "blob",
            ChunkRecordKind::StripeParity => "parity",
            ChunkRecordKind::TombstoneRef => "tombstone",
        };
        let address_kind = match r.address_kind {
            ChunkAddressKind::Raw => "raw",
            ChunkAddressKind::Convergent => "convergent",
        };
        let aead_kind = match r.aead_kind {
            ChunkAeadKind::AesGcm256 => "aes",
            ChunkAeadKind::ChaCha20Poly1305 => "chacha",
        };
        Self {
            kind,
            address_kind,
            aead_kind,
            compressed: r.compressed,
            format_aware: r.format_aware,
            length_plaintext: r.length_plaintext,
            chunk_id: r.chunk_id,
            ratchet_key_id: r.ratchet_key_id,
            ciphertext: r.ciphertext,
            stripe: PyStripe::from_rust(r.stripe_descriptor),
        }
    }
}

/// Python view of a stripe descriptor.
#[pyclass(
    from_py_object,
    name = "StripeDescriptor",
    module = "one_link_native.store",
    frozen
)]
#[derive(Debug, Clone)]
pub struct PyStripe {
    #[pyo3(get)]
    stripe_id_lo64: u64,
    // "data", "parity" or "not_striped": borrowed, so that a chunk lookup,
    // which returns one of these per call, does not allocate for it.
    #[pyo3(get)]
    role: &'static str,
    #[pyo3(get)]
    stripe_index: u8,
    #[pyo3(get)]
    stripe_k: u8,
    #[pyo3(get)]
    stripe_m: u8,
    #[pyo3(get)]
    cohort_id_lo64: u64,
}

#[pymethods]
impl PyStripe {
    #[new]
    #[pyo3(signature = (stripe_id_lo64=0, role="not_striped", stripe_index=0, stripe_k=0, stripe_m=0, cohort_id_lo64=0))]
    fn new(
        stripe_id_lo64: u64,
        role: &str,
        stripe_index: u8,
        stripe_k: u8,
        stripe_m: u8,
        cohort_id_lo64: u64,
    ) -> PyResult<Self> {
        // Validate the role and keep the name this module owns.
        let role = match role {
            "data" => "data",
            "parity" => "parity",
            "not_striped" => "not_striped",
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown stripe role '{other}'; expected 'data', 'parity', or 'not_striped'"
                )))
            }
        };
        Ok(Self {
            stripe_id_lo64,
            role,
            stripe_index,
            stripe_k,
            stripe_m,
            cohort_id_lo64,
        })
    }
}

impl PyStripe {
    fn from_rust(s: StripeDescriptor) -> Self {
        let role = match s.stripe_role {
            StripeRole::Data => "data",
            StripeRole::Parity => "parity",
            StripeRole::NotStriped => "not_striped",
        };
        Self {
            stripe_id_lo64: s.stripe_id_lo64,
            role,
            stripe_index: s.stripe_index,
            stripe_k: s.stripe_k,
            stripe_m: s.stripe_m,
            cohort_id_lo64: s.cohort_id_lo64,
        }
    }

    fn to_rust(&self) -> PyResult<StripeDescriptor> {
        let role = match self.role {
            "data" => StripeRole::Data,
            "parity" => StripeRole::Parity,
            "not_striped" => StripeRole::NotStriped,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown stripe role '{other}'"
                )))
            }
        };
        Ok(StripeDescriptor {
            stripe_id_lo64: self.stripe_id_lo64,
            stripe_role: role,
            stripe_index: self.stripe_index,
            stripe_k: self.stripe_k,
            stripe_m: self.stripe_m,
            cohort_id_lo64: self.cohort_id_lo64,
        })
    }
}

/// Python view of a chunk's on-disk location.
#[pyclass(
    from_py_object,
    name = "ChunkLocation",
    module = "one_link_native.store",
    frozen
)]
#[derive(Debug, Clone)]
pub struct PyChunkLocation {
    #[pyo3(get)]
    file_id: u64,
    #[pyo3(get)]
    wal_offset: u64,
    #[pyo3(get)]
    length_plaintext: u32,
    #[pyo3(get)]
    length_ciphertext: u32,
    ratchet_key_id: [u8; 16],
    #[pyo3(get)]
    stripe: PyStripe,
}

#[pymethods]
impl PyChunkLocation {
    #[getter]
    fn ratchet_key_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.ratchet_key_id)
    }
}

impl PyChunkLocation {
    fn from_rust(l: ChunkLocation) -> Self {
        Self {
            file_id: l.file_id,
            wal_offset: l.wal_offset,
            length_plaintext: l.length_plaintext,
            length_ciphertext: l.length_ciphertext,
            ratchet_key_id: l.ratchet_key_id,
            stripe: PyStripe::from_rust(l.stripe_descriptor),
        }
    }
}

/// The chunk store handle.
#[pyclass(name = "ChunkStore", module = "one_link_native.store", unsendable)]
pub struct PyChunkStore {
    inner: Option<ChunkStore>,
}

#[pymethods]
impl PyChunkStore {
    /// Append a chunk record to the `chunk_log`. Returns the offset.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        record_kind, address_kind, aead_kind,
        chunk_id, ratchet_key_id, length_plaintext, ciphertext,
        compressed=false, format_aware=false, stripe=None,
    ))]
    fn append_chunk(
        &mut self,
        record_kind: &str,
        address_kind: &str,
        aead_kind: &str,
        chunk_id: &[u8],
        ratchet_key_id: &[u8],
        length_plaintext: u32,
        ciphertext: &[u8],
        compressed: bool,
        format_aware: bool,
        stripe: Option<PyStripe>,
    ) -> PyResult<u64> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("ChunkStore is closed"))?;
        if ciphertext.len() > ol_chunk_store::MAX_CHUNK_CIPHERTEXT_LEN {
            return Err(PyValueError::new_err(format!(
                "ciphertext too large: {} > {}",
                ciphertext.len(),
                ol_chunk_store::MAX_CHUNK_CIPHERTEXT_LEN
            )));
        }
        let record = ChunkRecord {
            kind: parse_record_kind(record_kind)?,
            address_kind: parse_address_kind(address_kind)?,
            aead_kind: parse_aead_kind(aead_kind)?,
            compressed,
            format_aware,
            length_plaintext,
            chunk_id: check_chunk_id(chunk_id)?,
            ratchet_key_id: check_ratchet_id(ratchet_key_id)?,
            stripe_descriptor: match stripe {
                Some(s) => s.to_rust()?,
                None => StripeDescriptor::NONE,
            },
            ciphertext: ciphertext.to_vec(),
        };
        inner
            .append_chunk(&record)
            .map_err(chunk_store_error_to_pyerr)
    }

    /// Append a manifest record.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (record_kind, hlc_timestamp, actor_id, body, flags=0, chunk_log_anchor=0))]
    fn append_manifest(
        &mut self,
        record_kind: &str,
        hlc_timestamp: u64,
        actor_id: &[u8],
        body: &[u8],
        flags: u8,
        chunk_log_anchor: u64,
    ) -> PyResult<()> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("ChunkStore is closed"))?;
        if body.len() > ol_chunk_store::MAX_MANIFEST_BODY_LEN {
            return Err(PyValueError::new_err(format!(
                "manifest body too large: {} > {}",
                body.len(),
                ol_chunk_store::MAX_MANIFEST_BODY_LEN
            )));
        }
        let r = ManifestRecord {
            kind: parse_manifest_kind(record_kind)?,
            flags,
            hlc_timestamp,
            actor_id: check_actor_id(actor_id)?,
            chunk_log_anchor,
            body: body.to_vec(),
        };
        inner
            .append_manifest(&r)
            .map_err(chunk_store_error_to_pyerr)
    }

    /// Flush both logs to durable storage.
    fn flush(&mut self, py: Python<'_>) -> PyResult<()> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("ChunkStore is closed"))?;
        py.detach(|| inner.flush())
            .map_err(chunk_store_error_to_pyerr)
    }

    /// Check if a chunk exists.
    fn has_chunk(&self, chunk_id: &[u8]) -> PyResult<bool> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("ChunkStore is closed"))?;
        let id = check_chunk_id(chunk_id)?;
        Ok(inner.has_chunk(&id))
    }

    /// Get a chunk's location, or None.
    fn locate_chunk(&self, chunk_id: &[u8]) -> PyResult<Option<PyChunkLocation>> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("ChunkStore is closed"))?;
        let id = check_chunk_id(chunk_id)?;
        Ok(inner.locate_chunk(&id).map(PyChunkLocation::from_rust))
    }

    /// Read a full chunk record (header + ciphertext).
    fn read_chunk(&self, py: Python<'_>, chunk_id: &[u8]) -> PyResult<PyReadChunk> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("ChunkStore is closed"))?;
        let id = check_chunk_id(chunk_id)?;
        let r = py
            .detach(|| inner.read_chunk(&id))
            .map_err(chunk_store_error_to_pyerr)?;
        Ok(PyReadChunk::from_rust(r))
    }

    /// Snapshot of replay + write counters.
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyDict>> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("ChunkStore is closed"))?;
        let s = inner.stats();
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("indexed_chunks", s.indexed_chunks)?;
        dict.set_item("manifest_records", s.manifest_records)?;
        dict.set_item("bytes_scanned_at_replay", s.bytes_scanned_at_replay)?;
        dict.set_item("files_truncated", s.files_truncated)?;
        dict.set_item("orphaned_manifest_records", s.orphaned_manifest_records)?;
        Ok(dict)
    }

    /// Close, flushing both logs.
    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(mut inner) = self.inner.take() {
            py.detach(|| inner.close())
                .map_err(chunk_store_error_to_pyerr)?;
        }
        Ok(())
    }
}

/// Open or create a chunk store rooted at `root`.
#[pyfunction]
fn open_store(py: Python<'_>, root: &str) -> PyResult<PyChunkStore> {
    let path = PathBuf::from(root);
    let inner = py
        .detach(|| ChunkStore::open(&path))
        .map_err(chunk_store_error_to_pyerr)?;
    Ok(PyChunkStore { inner: Some(inner) })
}

pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    use ol_chunk_store::{
        CHUNK_RECORD_HEADER_LEN, MANIFEST_RECORD_HEADER_LEN, STRIPE_DESCRIPTOR_LEN,
    };
    m.add("CHUNK_RECORD_HEADER_LEN", CHUNK_RECORD_HEADER_LEN)?;
    m.add("MANIFEST_RECORD_HEADER_LEN", MANIFEST_RECORD_HEADER_LEN)?;
    m.add("STRIPE_DESCRIPTOR_LEN", STRIPE_DESCRIPTOR_LEN)?;
    m.add(
        "MAX_CHUNK_CIPHERTEXT_LEN",
        ol_chunk_store::MAX_CHUNK_CIPHERTEXT_LEN,
    )?;
    m.add(
        "MAX_MANIFEST_BODY_LEN",
        ol_chunk_store::MAX_MANIFEST_BODY_LEN,
    )?;

    m.add_class::<PyStripe>()?;
    m.add_class::<PyChunkLocation>()?;
    m.add_class::<PyReadChunk>()?;
    m.add_class::<PyChunkStore>()?;
    m.add_function(wrap_pyfunction!(open_store, m)?)?;
    Ok(())
}
