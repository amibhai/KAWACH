//! The hash chain and its canonical encoding (DESIGN.md §7.1, §7.2).
//!
//! ```text
//! H_0 = SHA256( "kawach/audit/genesis/v1" ‖ instance_id )
//! H_n = SHA256( "kawach/audit/entry/v1"   ‖ H_{n-1} ‖ canonical(entry_n) )
//! ```
//!
//! ## Why the hash is not computed over the JSON
//!
//! Records are stored as JSONL so they stay greppable and recoverable with ordinary
//! tools, but the chain is computed over a **structural** encoding derived from the
//! parsed event, never over the serialised text.
//!
//! Hashing JSON text is a well-known footgun — key ordering, whitespace, Unicode
//! escaping, and number formatting all vary between serialisers and versions, so a log
//! written by one build can fail to verify under the next. Guaranteeing deterministic
//! *key order* (with `BTreeMap`, say) does not fix this; it addresses one of four
//! failure modes and leaves the encoder's formatting decisions in the trusted path.
//!
//! So an event contributes an ordered list of `(name, value)` pairs via
//! [`CanonicalPayload`], and those pairs are encoded directly. Verification re-derives
//! the same structure from the parsed record, which means **reformatting the JSON — or
//! changing serialiser version — cannot break verification**, while altering any
//! semantic field still breaks the chain. That is the property we actually want.
//!
//! ## Why every field is length-prefixed
//!
//! Without length prefixes, `actor="a" kind="bc"` and `actor="ab" kind="c"` encode to
//! identical bytes and therefore hash identically. An adversary who controls one field
//! could then forge another while keeping the digest intact. Prefixing every field with
//! its length, and prefixing the field *list* with its count, makes the boundaries
//! unambiguous.

use core::fmt;

use sha2::{Digest, Sha256};

use kawach_core::hex;

/// Domain separator for the genesis hash.
const DOMAIN_GENESIS: &[u8] = b"kawach/audit/genesis/v1";
/// Domain separator for every chained entry.
const DOMAIN_ENTRY: &[u8] = b"kawach/audit/entry/v1";
/// Domain separator for checkpoint signatures.
pub(crate) const DOMAIN_CHECKPOINT: &[u8] = b"kawach/audit/checkpoint/v1";

/// A 256-bit chain hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryHash([u8; 32]);

impl EntryHash {
    /// The chain's starting value, bound to the instance identifier.
    ///
    /// Binding to `instance_id` means a log lifted from one KAWACH installation does not
    /// verify under another, so an adversary cannot substitute a wholesale replacement
    /// chain harvested from a different (perhaps deliberately boring) instance.
    #[must_use]
    pub fn genesis(instance_id: &str) -> Self {
        let mut h = Sha256::new();
        h.update(DOMAIN_GENESIS);
        h.update(instance_id.as_bytes());
        Self(h.finalize().into())
    }

    /// Chain one entry onto this hash.
    #[must_use]
    pub fn chain(&self, canonical: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(DOMAIN_ENTRY);
        h.update(self.0);
        h.update(canonical);
        Self(h.finalize().into())
    }

    /// Raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse from lowercase or uppercase hex.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        let raw = hex::decode(s.trim())?;
        let arr: [u8; 32] = raw.try_into().ok()?;
        Some(Self(arr))
    }

    /// Short form for human-facing output.
    #[must_use]
    pub fn short(&self) -> String {
        hex::encode(&self.0[..6])
    }
}

impl fmt::Display for EntryHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for EntryHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EntryHash({})", self.short())
    }
}

impl serde::Serialize for EntryHash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for EntryHash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).ok_or_else(|| serde::de::Error::custom("malformed chain hash"))
    }
}

/// An event's contribution to the canonical encoding.
///
/// Implementors expose a stable kind name and an **ordered** list of `(field, value)`
/// pairs. Order is part of the contract: reordering fields changes the hash, so the
/// order must be fixed by the implementation rather than by a map's iteration order.
pub trait CanonicalPayload {
    /// Stable discriminant, e.g. `access_intent`. Never renamed once released — the
    /// kind is inside the hash, so renaming one invalidates every historical entry.
    fn kind(&self) -> &'static str;

    /// Ordered `(name, value)` pairs. Every semantically meaningful field must appear;
    /// a field omitted here is a field an adversary can change without breaking the
    /// chain.
    fn fields(&self) -> Vec<(&'static str, String)>;
}

/// Append `len(bytes)` as little-endian `u32`, then the bytes.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = bytes.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Build the canonical encoding of one entry.
///
/// ```text
/// canonical := u64_le(seq)
///            ‖ lp(prev_hash) ‖ lp(timestamp) ‖ lp(actor) ‖ lp(run)
///            ‖ lp(kind) ‖ u32_le(field_count)
///            ‖ for each field: lp(name) ‖ lp(value)
/// ```
///
/// The field *count* is included so that fields cannot be spliced across the boundary
/// between the header and the payload.
#[must_use]
pub fn canonical_entry(
    seq: u64,
    prev: &EntryHash,
    timestamp: &str,
    actor: &str,
    run: &str,
    payload: &dyn CanonicalPayload,
) -> Vec<u8> {
    let fields = payload.fields();
    let mut out = Vec::with_capacity(128);

    out.extend_from_slice(&seq.to_le_bytes());
    push_lp(&mut out, prev.as_bytes());
    push_lp(&mut out, timestamp.as_bytes());
    push_lp(&mut out, actor.as_bytes());
    push_lp(&mut out, run.as_bytes());
    push_lp(&mut out, payload.kind().as_bytes());

    #[allow(clippy::cast_possible_truncation)]
    let count = fields.len() as u32;
    out.extend_from_slice(&count.to_le_bytes());
    for (name, value) in &fields {
        push_lp(&mut out, name.as_bytes());
        push_lp(&mut out, value.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Payload(&'static str, Vec<(&'static str, String)>);
    impl CanonicalPayload for Payload {
        fn kind(&self) -> &'static str {
            self.0
        }
        fn fields(&self) -> Vec<(&'static str, String)> {
            self.1.clone()
        }
    }

    fn p(kind: &'static str, fields: &[(&'static str, &str)]) -> Payload {
        Payload(kind, fields.iter().map(|(k, v)| (*k, (*v).to_owned())).collect())
    }

    #[test]
    fn genesis_is_bound_to_the_instance() {
        assert_ne!(EntryHash::genesis("kawach-prod"), EntryHash::genesis("kawach-staging"));
        assert_eq!(EntryHash::genesis("kawach-prod"), EntryHash::genesis("kawach-prod"));
    }

    #[test]
    fn chaining_is_deterministic_and_order_dependent() {
        let g = EntryHash::genesis("i");
        let a = canonical_entry(1, &g, "t", "alice", "r", &p("k", &[("f", "v")]));
        let b = canonical_entry(2, &g, "t", "alice", "r", &p("k", &[("f", "v")]));
        assert_eq!(g.chain(&a), g.chain(&a), "hashing must be deterministic");
        assert_ne!(g.chain(&a), g.chain(&b), "the sequence number must be committed to");
    }

    #[test]
    fn length_prefixing_prevents_field_boundary_forgery() {
        // The attack the prefixes exist to stop: without them, these two encodings are
        // byte-identical, so an adversary controlling the actor could shift a character
        // into the kind and keep the digest unchanged.
        let g = EntryHash::genesis("i");
        let x = canonical_entry(1, &g, "t", "a", "r", &p("bc", &[]));
        let y = canonical_entry(1, &g, "t", "ab", "r", &p("c", &[]));
        assert_ne!(x, y, "field boundaries are ambiguous — the encoding is forgeable");
    }

    #[test]
    fn field_values_cannot_be_shifted_between_adjacent_fields() {
        let g = EntryHash::genesis("i");
        let x = canonical_entry(1, &g, "t", "a", "r", &p("k", &[("one", "ab"), ("two", "c")]));
        let y = canonical_entry(1, &g, "t", "a", "r", &p("k", &[("one", "a"), ("two", "bc")]));
        assert_ne!(x, y);
    }

    #[test]
    fn adding_a_field_changes_the_encoding_even_if_it_is_empty() {
        // The field count is committed to, so an adversary cannot append or drop an
        // empty field to alter meaning while preserving the concatenated bytes.
        let g = EntryHash::genesis("i");
        let x = canonical_entry(1, &g, "t", "a", "r", &p("k", &[("one", "v")]));
        let y = canonical_entry(1, &g, "t", "a", "r", &p("k", &[("one", "v"), ("two", "")]));
        assert_ne!(x, y);
    }

    #[test]
    fn every_header_component_is_committed_to() {
        let g = EntryHash::genesis("i");
        let base = canonical_entry(1, &g, "t1", "alice", "run1", &p("k", &[("f", "v")]));
        let variants = [
            canonical_entry(1, &g, "t2", "alice", "run1", &p("k", &[("f", "v")])),
            canonical_entry(1, &g, "t1", "mallory", "run1", &p("k", &[("f", "v")])),
            canonical_entry(1, &g, "t1", "alice", "run2", &p("k", &[("f", "v")])),
            canonical_entry(1, &g, "t1", "alice", "run1", &p("other", &[("f", "v")])),
            canonical_entry(1, &g, "t1", "alice", "run1", &p("k", &[("f", "w")])),
            canonical_entry(1, &g, "t1", "alice", "run1", &p("k", &[("g", "v")])),
            canonical_entry(1, &EntryHash::genesis("j"), "t1", "alice", "run1", &p("k", &[("f", "v")])),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(&base, v, "variant {i} is not distinguished by the encoding");
        }
    }

    #[test]
    fn hashes_round_trip_through_hex() {
        let h = EntryHash::genesis("kawach-prod");
        assert_eq!(EntryHash::from_hex(&h.to_hex()).unwrap(), h);
        assert_eq!(h.to_hex().len(), 64);
        assert!(EntryHash::from_hex("not-hex").is_none());
        assert!(EntryHash::from_hex("aabb").is_none());
    }

    #[test]
    fn hash_debug_is_abbreviated_not_absent() {
        let h = EntryHash::genesis("i");
        assert!(format!("{h:?}").contains(&h.short()));
    }
}
