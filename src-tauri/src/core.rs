//! Protocol-independent safety primitives. Networking code must use these before I/O.
use blake3::Hasher;
use rand::RngCore;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Error, PartialEq)]
pub enum PathError {
    #[error("empty path")]
    Empty,
    #[error("unsafe path component")]
    Unsafe,
    #[error("Windows-incompatible filename")]
    Windows,
}

/// Canonical byte transcript; length-prefixing prevents concatenation ambiguity.
pub fn pairing_transcript(
    initiator_id: &str,
    responder_id: &str,
    initiator_host: &[u8],
    responder_host: &[u8],
    initiator_client: &[u8],
    responder_client: &[u8],
    initiator_nonce: &[u8; 32],
    responder_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    for part in [
        initiator_id.as_bytes(),
        responder_id.as_bytes(),
        initiator_host,
        responder_host,
        initiator_client,
        responder_client,
        initiator_nonce,
        responder_nonce,
    ] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}
pub fn confirmation_code(transcript: &[u8]) -> String {
    let hash = blake3::hash(transcript);
    let mut n = [0u8; 8];
    n.copy_from_slice(&hash.as_bytes()[..8]);
    format!("{:08}", u64::from_be_bytes(n) % 100_000_000)
}
pub fn fresh_nonce() -> [u8; 32] {
    let mut n = [0; 32];
    rand::thread_rng().fill_bytes(&mut n);
    n
}
pub fn fingerprint(public_key: &[u8]) -> String {
    let mut h = Hasher::new();
    h.update(public_key);
    hex::encode(&h.finalize().as_bytes()[..8])
}

/// Validate a remote-provided relative path before joining it to a staging root.
pub fn safe_relative_path(value: &str) -> Result<PathBuf, PathError> {
    if value.is_empty() {
        return Err(PathError::Empty);
    }
    let p = Path::new(value);
    if p.is_absolute() {
        return Err(PathError::Unsafe);
    }
    for c in p.components() {
        match c {
            Component::Normal(name) => {
                let s = name.to_string_lossy();
                if s.is_empty()
                    || s == "."
                    || s.contains(':')
                    || s.chars()
                        .any(|x| matches!(x, '<' | '>' | '"' | '|' | '?' | '*'))
                    || s.ends_with('.')
                    || s.ends_with(' ')
                {
                    return Err(PathError::Windows);
                }
            }
            _ => return Err(PathError::Unsafe),
        }
    }
    Ok(p.to_path_buf())
}
pub fn collision_name(name: &str, exists: impl Fn(&Path) -> bool) -> String {
    let path = Path::new(name);
    if !exists(path) {
        return name.to_owned();
    }
    let stem = path.file_stem().and_then(|v| v.to_str()).unwrap_or("file");
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| format!(".{v}"))
        .unwrap_or_default();
    for n in 1.. {
        let candidate = format!("{stem} ({n}){ext}");
        if !exists(Path::new(&candidate)) {
            return candidate;
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn code_is_eight_digits_and_stable() {
        let c = confirmation_code(b"henad vector 1");
        assert_eq!(c, confirmation_code(b"henad vector 1"));
        assert_eq!(c.len(), 8);
        assert!(c.bytes().all(|b| b.is_ascii_digit()));
    }
    #[test]
    fn transcript_is_unambiguous() {
        let n = [0; 32];
        assert_ne!(
            pairing_transcript("a", "bc", b"d", b"e", b"f", b"g", &n, &n),
            pairing_transcript("ab", "c", b"d", b"e", b"f", b"g", &n, &n)
        );
    }
    #[test]
    fn rejects_bad_paths() {
        for p in ["../x", "/x", "a/../../b", "C:/x", "a/<x"] {
            assert!(safe_relative_path(p).is_err(), "{p}");
        }
        assert_eq!(
            safe_relative_path("folder/file.txt").unwrap(),
            PathBuf::from("folder/file.txt")
        );
    }
    #[test]
    fn resolves_collisions() {
        assert_eq!(
            collision_name("a.txt", |p| p == Path::new("a.txt")
                || p == Path::new("a (1).txt")),
            "a (2).txt"
        );
    }
}
