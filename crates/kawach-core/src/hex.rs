//! Minimal hex codec.
//!
//! Hand-rolled rather than imported: it is fifteen lines, it is on the path that
//! encodes audit-chain hashes, and every avoided dependency is one fewer party with
//! read access to our address space (DESIGN.md §13, P6).

/// Encode bytes as lowercase hex.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode lowercase or uppercase hex.
///
/// # Errors
/// Returns `None` for odd-length input or non-hex characters.
#[must_use]
pub fn decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let data = [0x00, 0x0f, 0xf0, 0xff, 0x42];
        assert_eq!(encode(&data), "000ff0ff42");
        assert_eq!(decode("000ff0ff42").unwrap(), data);
        assert_eq!(decode("000FF0FF42").unwrap(), data);
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(decode("abc").is_none());
        assert!(decode("zz").is_none());
    }
}
