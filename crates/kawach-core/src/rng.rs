//! The single CSPRNG entry point.
//!
//! Centralised so that "where does randomness come from" has exactly one answer during
//! review, and so no call site can accidentally reach for a seedable or thread-local
//! generator when producing credential material.

use rand::RngCore;

/// Fill `buf` with cryptographically secure random bytes from the OS.
///
/// # Panics
/// Panics if the OS entropy source is unavailable. This is deliberate: silently
/// continuing with degraded randomness while generating a credential would be worse
/// than a crash, and there is no meaningful recovery.
pub(crate) fn fill(buf: &mut [u8]) {
    rand::rngs::OsRng.fill_bytes(buf);
}

/// A lowercase-hex identifier of `bytes` random bytes.
pub(crate) fn hex_id(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    fill(&mut raw);
    crate::hex::encode(&raw)
}
