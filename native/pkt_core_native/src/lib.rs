// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 pkt-core contributors
//
// pkt_core_native — optional Rust accelerator for pkt-core's crypto hot path.
//
// It implements the three 128-bit block ciphers Packet Tracer uses (Twofish,
// Serpent, CAST-256) in ECB / encrypt-only form, mirroring the seam of
// `pkt_core.crypto.ciphers.BlockCipher`.  Everything above this module (CMAC,
// CTR, the Crypto++ EAX variant) stays in Python and only calls
// `encrypt_block`, so the backend is a drop-in third choice behind libgcrypt
// and the pure-Python implementation.
//
// The Python package must import cleanly when this module is absent; it is a
// pure accelerator, never a requirement.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

mod cast256;
mod cast_tables;
mod serpent;
mod twofish;

const BLOCK_SIZE: usize = 16;

/// Cipher names accepted by :func:`Cipher` — the registry names of
/// ``pkt_core.crypto.ciphers`` (minus ``aes``, which this crate does not
/// implement; libgcrypt still covers it).
const NAMES: [&str; 5] = [
    "twofish",
    "serpent128",
    "serpent192",
    "serpent256",
    "cast256",
];

enum Impl {
    Twofish(twofish::Twofish),
    Serpent(serpent::Serpent),
    Cast256(cast256::Cast256),
}

impl Impl {
    fn encrypt_block(&self, block: &[u8]) -> [u8; BLOCK_SIZE] {
        match self {
            Impl::Twofish(c) => c.encrypt_block(block),
            Impl::Serpent(c) => c.encrypt_block(block),
            Impl::Cast256(c) => c.encrypt_block(block),
        }
    }

    fn key_size(&self) -> usize {
        match self {
            Impl::Twofish(c) => c.key_size(),
            Impl::Serpent(c) => c.key_size(),
            Impl::Cast256(c) => c.key_size(),
        }
    }

    fn decrypt_block(&self, block: &[u8]) -> Option<[u8; BLOCK_SIZE]> {
        match self {
            Impl::Cast256(c) => Some(c.decrypt_block(block)),
            _ => None,
        }
    }

    fn cast256_schedule(&self) -> Option<([[u32; 4]; 12], [[u32; 4]; 12])> {
        match self {
            Impl::Cast256(c) => Some(c.schedule()),
            _ => None,
        }
    }

    fn cast256_quad_round(
        &self,
        state: [u32; 4],
        index: usize,
        forward: bool,
    ) -> Option<[u32; 4]> {
        match self {
            Impl::Cast256(c) => Some(c.quad_round(state, index, forward)),
            _ => None,
        }
    }
}

/// A keyed block cipher: 16 bytes in, 16 bytes out (ECB, encrypt only).
///
/// The attribute surface matches ``pkt_core.crypto.ciphers.BlockCipher``:
/// ``block_size``, ``key_size`` and ``encrypt_block(block) -> bytes``.
#[pyclass(name = "Cipher", module = "pkt_core_native")]
struct PyCipher {
    inner: Impl,
    name: String,
}

fn key_size_error(name: &str, len: usize) -> PyErr {
    PyValueError::new_err(format!("{name} rejected a {len}-byte key"))
}

impl PyCipher {
    fn build(name: &str, key: &[u8]) -> PyResult<Self> {
        let inner = match name {
            "twofish" => {
                if !matches!(key.len(), 16 | 24 | 32) {
                    return Err(key_size_error(name, key.len()));
                }
                Impl::Twofish(twofish::Twofish::new(key).map_err(PyValueError::new_err)?)
            }
            "serpent128" | "serpent192" | "serpent256" => {
                let expected = match name {
                    "serpent128" => 16,
                    "serpent192" => 24,
                    _ => 32,
                };
                if key.len() != expected {
                    return Err(key_size_error(name, key.len()));
                }
                Impl::Serpent(serpent::Serpent::new(key).map_err(PyValueError::new_err)?)
            }
            "cast256" => {
                if !(16..=32).contains(&key.len()) || key.len() % 4 != 0 {
                    return Err(key_size_error(name, key.len()));
                }
                Impl::Cast256(cast256::Cast256::new(key).map_err(PyValueError::new_err)?)
            }
            other => {
                return Err(PyValueError::new_err(format!(
                    "pkt_core_native has no cipher named {other:?}; known: {NAMES:?}"
                )))
            }
        };
        Ok(Self {
            inner,
            name: name.to_string(),
        })
    }
}

#[pymethods]
impl PyCipher {
    #[new]
    fn new(name: &str, key: &[u8]) -> PyResult<Self> {
        Self::build(name, key)
    }

    /// Always 16 — every cipher Packet Tracer uses is a 128-bit block cipher.
    #[getter]
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    /// Length of the key this instance was constructed with.
    #[getter]
    fn key_size(&self) -> usize {
        self.inner.key_size()
    }

    /// The registry name this instance was constructed with.
    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    /// Encrypt one 16-byte block and return the 16-byte ciphertext.
    fn encrypt_block<'py>(&self, py: Python<'py>, block: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if block.len() != BLOCK_SIZE {
            return Err(PyValueError::new_err(format!(
                "block must be {BLOCK_SIZE} bytes, got {}",
                block.len()
            )));
        }
        Ok(PyBytes::new(py, &self.inner.encrypt_block(block)))
    }

    /// Encrypt a whole buffer of complete 16-byte blocks (bulk ECB).
    ///
    /// This amortises the Python/Rust crossing for callers that have many
    /// blocks available; ``encrypt_block`` remains the compatibility seam.
    fn encrypt_blocks<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if data.len() % BLOCK_SIZE != 0 {
            return Err(PyValueError::new_err(format!(
                "data length must be a multiple of {BLOCK_SIZE}, got {}",
                data.len()
            )));
        }
        let mut out = vec![0u8; data.len()];
        for (src, dst) in data.chunks_exact(BLOCK_SIZE).zip(out.chunks_exact_mut(BLOCK_SIZE)) {
            dst.copy_from_slice(&self.inner.encrypt_block(src));
        }
        Ok(PyBytes::new(py, &out))
    }

    /// CAST-256 only: the inverse of :meth:`encrypt_block`.
    ///
    /// CAST-256 decryption is exactly the encryption structure with the
    /// quad-round keys reversed (RFC 2612 section 2.3).  Twofish and Serpent
    /// are encrypt-only in this crate — the container format never decrypts
    /// with them — so those raise :class:`ValueError`.
    fn decrypt_block<'py>(&self, py: Python<'py>, block: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if block.len() != BLOCK_SIZE {
            return Err(PyValueError::new_err(format!(
                "block must be {BLOCK_SIZE} bytes, got {}",
                block.len()
            )));
        }
        match self.inner.decrypt_block(block) {
            Some(out) => Ok(PyBytes::new(py, &out)),
            None => Err(PyValueError::new_err(
                "decrypt_block is only implemented for cast256",
            )),
        }
    }

    /// CAST-256 only: the derived quad-round keys ``(kr, km)`` (RFC 2612
    /// section 2.2), exposed so the appendix-A intermediate values can be
    /// checked from Python.
    fn key_schedule(
        &self,
    ) -> PyResult<(
        Vec<(u32, u32, u32, u32)>,
        Vec<(u32, u32, u32, u32)>,
    )> {
        match self.inner.cast256_schedule() {
            Some((kr, km)) => Ok((
                kr.iter().map(|q| (q[0], q[1], q[2], q[3])).collect(),
                km.iter().map(|q| (q[0], q[1], q[2], q[3])).collect(),
            )),
            None => Err(PyValueError::new_err(
                "key_schedule is only implemented for cast256",
            )),
        }
    }

    /// CAST-256 only: one quad-round ``Q_i`` / ``QBAR_i`` of RFC 2612
    /// section 2.3, exposed so the appendix-A intermediate values can be
    /// checked from Python (the pure-Python class exposes the same step).
    #[pyo3(signature = (state, index, forward = true))]
    fn cast256_quad_round(
        &self,
        state: (u32, u32, u32, u32),
        index: usize,
        forward: bool,
    ) -> PyResult<(u32, u32, u32, u32)> {
        let input = [state.0, state.1, state.2, state.3];
        match self.inner.cast256_quad_round(input, index, forward) {
            Some(out) => Ok((out[0], out[1], out[2], out[3])),
            None => Err(PyValueError::new_err(
                "cast256_quad_round is only implemented for cast256",
            )),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "pkt_core_native.Cipher({:?}, key_size={})",
            self.name,
            self.inner.key_size()
        )
    }
}

/// Names of the block ciphers this accelerator implements.
#[pyfunction]
fn available_ciphers() -> Vec<&'static str> {
    NAMES.to_vec()
}

/// Version string of the native module (mirrors the crate version).
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn pkt_core_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyCipher>()?;
    m.add_function(wrap_pyfunction!(available_ciphers, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("BLOCK_SIZE", BLOCK_SIZE)?;
    Ok(())
}
