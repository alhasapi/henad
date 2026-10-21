//! Protocol-independent safety primitives. Networking code must use these before I/O.
use blake3::Hasher;
use rand::RngCore;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 2;
/// Control frames are small JSON messages; anything larger is a bug or an attack.
pub const MAX_FRAME: usize = 64 * 1024;

#[derive(Debug, Error, PartialEq)]
pub enum PathError {
    #[error("empty path")]
    Empty,
    #[error("unsafe path component")]
    Unsafe,
    #[error("Windows-incompatible filename")]
    Windows,
}

#[derive(Debug, Error, PartialEq)]
pub enum FrameError {
    #[error("frame exceeds the {MAX_FRAME} byte limit")]
    TooLarge,
    #[error("truncated frame")]
    Truncated,
}

/// Canonical byte transcript; length-prefixing prevents concatenation ambiguity.
///
/// Both peers must contribute their own nonce, so neither side can force a
/// transcript the other did not agree to.
#[allow(clippy::too_many_arguments)]
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

pub fn transcript_hash(transcript: &[u8]) -> [u8; 32] {
    *blake3::hash(transcript).as_bytes()
}

/// Eight decimal digits derived from the transcript hash.
pub fn confirmation_code(transcript: &[u8]) -> String {
    let hash = blake3::hash(transcript);
    let mut n = [0u8; 8];
    n.copy_from_slice(&hash.as_bytes()[..8]);
    format!("{:08}", u64::from_be_bytes(n) % 100_000_000)
}

/// Presentation helper: pairs of digits are easier to compare across screens.
pub fn format_code(code: &str) -> String {
    code.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
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
                    || s.chars().any(|x| (x as u32) < 0x20)
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

/// Length-prefixed control frame: `u32` big-endian length followed by the payload.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Consume exactly one frame from `buf`, if a complete one is buffered.
pub fn decode_frame(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, FrameError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let payload = buf[4..4 + len].to_vec();
    buf.drain(..4 + len);
    Ok(Some(payload))
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
        assert_eq!(format_code("12345678"), "1234 5678");
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
    fn distinct_nonces_produce_distinct_codes() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let one = pairing_transcript("i", "r", b"ih", b"rh", b"ic", b"rc", &a, &b);
        let two = pairing_transcript("i", "r", b"ih", b"rh", b"ic", b"rc", &a, &a);
        assert_ne!(confirmation_code(&one), confirmation_code(&two));
    }

    #[test]
    fn rejects_bad_paths() {
        for p in ["../x", "/x", "a/../../b", "C:/x", "a/<x", "a/b.", "a/b "] {
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

    #[test]
    fn frames_round_trip_and_split() {
        let frame = encode_frame(b"hello").unwrap();
        let mut buf = frame[..3].to_vec();
        assert_eq!(decode_frame(&mut buf).unwrap(), None);
        buf.extend_from_slice(&frame[3..]);
        assert_eq!(decode_frame(&mut buf).unwrap(), Some(b"hello".to_vec()));
        assert!(buf.is_empty());
    }

    #[test]
    fn frames_reject_oversize_lengths() {
        assert_eq!(
            encode_frame(&vec![0u8; MAX_FRAME + 1]),
            Err(FrameError::TooLarge)
        );
        let mut buf = ((MAX_FRAME as u32) + 1).to_be_bytes().to_vec();
        assert_eq!(decode_frame(&mut buf), Err(FrameError::TooLarge));
    }
}
