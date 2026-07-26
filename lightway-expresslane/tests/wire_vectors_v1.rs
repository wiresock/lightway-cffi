//! Golden wire-format vector for protocol **Version1**.
//!
//! Companion to `wire_vectors.rs`, which pins Version2. It is a separate file
//! on purpose: `wire_vectors.rs` is the artifact that proves the AES-GCM
//! provider swap did not move the wire, and it is worth being able to show it
//! byte-identical to the pre-swap commit. Adding to it would spend that.
//!
//! Why V1 needs its own pin at all: the only V1 coverage otherwise is
//! `session.rs`'s round-trip and cross-version tests, and those encrypt and
//! decrypt with the same `build_aad`. They therefore pass under ANY
//! self-consistent AAD convention — make `build_aad` emit 18 bytes
//! unconditionally, or swap V1's `session_id` and `counter`, and they stay
//! green while the wire silently breaks against a server running upstream
//! `lightway-core`. This vector is what fails in that case.
//!
//! The inputs are deliberately identical to `GOLDEN_V2`'s. AAD length is then
//! the sole difference between the two packets, which is exactly the
//! `version >= Version2` boundary in `build_aad`: the ciphertexts are equal
//! (the keystream does not depend on the AAD) and only the tags differ.

use lightway_expresslane::{ExpresslaneKey, ExpresslaneSession, ExpresslaneVersion};

/// V1 packet, key=[0x42;32], session_id=01..08, counter=1, iv=[0x09;12],
/// plaintext="expresslane golden vector" (25 bytes), is_encoded=false.
///
/// Layout: counter(8) | iv(12) | tag(16) | data_len(2, BE) | flags(2, BE) |
/// ciphertext(25). Total 65 bytes. The flags field is present on the wire for
/// V1 as well; it is simply not bound into the AAD.
const GOLDEN_V1: &str = "0000000000000001\
090909090909090909090909\
f48a6db842e8b2f97cfbe8a39ca83464\
0019\
0000\
58b1d91834ea34259ee915adb156c9280a40229f78cd5b7e71";

const KEY: [u8; 32] = [0x42u8; 32];
const SESSION_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const IV: [u8; 12] = [0x09u8; 12];
const PLAINTEXT: &[u8] = b"expresslane golden vector";

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex vector must have an even number of digits");
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex vector is ASCII");
            u8::from_str_radix(pair, 16).expect("valid hex digit pair")
        })
        .collect()
}

#[test]
fn v1_encrypt_matches_golden_vector() {
    let session = ExpresslaneSession::new(ExpresslaneVersion::Version1);
    session.update_next_self_key(ExpresslaneKey(KEY)).unwrap();
    session.promote_self_key();

    let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + PLAINTEXT.len()];
    let n = session.encrypt(1, SESSION_ID, PLAINTEXT, IV, false, &mut out).unwrap();
    out.truncate(n);

    let expected = decode_hex(GOLDEN_V1);
    assert_eq!(
        out,
        expected,
        "V1 encrypt drifted from the pinned wire vector\n got: {}\nwant: {}",
        out.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        GOLDEN_V1,
    );

    // Structural sanity on the pinned bytes (independent of the AEAD backend).
    assert_eq!(&expected[0..8], &1u64.to_be_bytes(), "counter");
    assert_eq!(&expected[8..20], &IV, "iv");
    assert_eq!(u16::from_be_bytes([expected[36], expected[37]]) as usize, PLAINTEXT.len(), "data_len");
    assert_eq!(&expected[38..40], &[0, 0], "flags: encoded clear, reserved zero");
}

#[test]
fn v1_golden_vector_decrypts_back_to_plaintext() {
    let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version1);
    receiver.update_peer_key(ExpresslaneKey(KEY)).unwrap();

    let wire = decode_hex(GOLDEN_V1);
    let mut out = vec![0u8; PLAINTEXT.len()];
    let (len, is_encoded) = receiver.decrypt(SESSION_ID, &wire, &mut out).unwrap();
    assert_eq!(&out[..len], PLAINTEXT);
    assert!(!is_encoded);
}

#[test]
fn v1_and_v2_differ_only_in_the_tag() {
    // Turns the pair of vectors into an assertion about *what* the version
    // boundary controls: AAD only. If someone makes V1 bind the flags, or makes
    // V2 stop binding them, this fails even if both files were regenerated
    // together — the ciphertexts would still match but the tags would collapse
    // to equal.
    let v1 = decode_hex(GOLDEN_V1);
    let v2 = decode_hex(
        "0000000000000001\
090909090909090909090909\
cd57bbb8026b4faf70e457412a1f6ef6\
0019\
0000\
58b1d91834ea34259ee915adb156c9280a40229f78cd5b7e71",
    );

    assert_eq!(v1[0..20], v2[0..20], "counter and iv");
    assert_ne!(v1[20..36], v2[20..36], "tag must differ: V2 binds flags into the AAD");
    assert_eq!(v1[36..], v2[36..], "data_len, flags and ciphertext are AAD-independent");
}
