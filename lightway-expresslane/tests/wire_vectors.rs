//! Golden wire-format vectors.
//!
//! `lightway-expresslane` is an independent reimplementation of the ExpressLane
//! data-packet protocol that must stay byte-for-byte interoperable with
//! `lightway-core`'s wolfssl-backed `ExpresslaneData` (a real Lightway server
//! terminates the other end). A full cross-crate interop test — encrypt via a
//! live `he_conn_t`, decrypt via `he_expresslane_session_t`, and vice versa —
//! needs a TLS handshake harness and is tracked as follow-up (see the design
//! doc's "Accepted risk: implementation drift").
//!
//! These fixed vectors are the lighter-weight guard in the meantime: they pin
//! the exact wire bytes for known inputs, so any drift in field layout,
//! endianness, `is_encoded`/reserved flag handling, or AAD construction fails
//! CI. The vector is also a concrete artifact that can be cross-checked by
//! hand against `lightway-core` output for the same key/session/counter/iv.

use lightway_expresslane::{ExpresslaneKey, ExpresslaneSession, ExpresslaneVersion};

/// V2 packet, key=[0x42;32], session_id=01..08, counter=1, iv=[0x09;12],
/// plaintext="expresslane golden vector" (25 bytes), is_encoded=false.
///
/// Layout: counter(8) | iv(12) | tag(16) | data_len(2, BE) | flags(2, BE) |
/// ciphertext(25). Total 65 bytes.
const GOLDEN_V2: &str = "0000000000000001\
090909090909090909090909\
cd57bbb8026b4faf70e457412a1f6ef6\
0019\
0000\
58b1d91834ea34259ee915adb156c9280a40229f78cd5b7e71";

const KEY: [u8; 32] = [0x42u8; 32];
const SESSION_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const IV: [u8; 12] = [0x09u8; 12];
const PLAINTEXT: &[u8] = b"expresslane golden vector";

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex vector must have an even number of digits");
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex vector is ASCII");
            u8::from_str_radix(pair, 16).expect("valid hex digit pair")
        })
        .collect()
}

#[test]
fn v2_encrypt_matches_golden_vector() {
    let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
    session.update_next_self_key(ExpresslaneKey(KEY)).unwrap();
    session.promote_self_key();

    let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + PLAINTEXT.len()];
    let n = session.encrypt(1, SESSION_ID, PLAINTEXT, IV, false, &mut out).unwrap();
    out.truncate(n);

    let expected = decode_hex(GOLDEN_V2);
    assert_eq!(
        out,
        expected,
        "encrypt drifted from the pinned wire vector\n got: {}\nwant: {}",
        out.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        GOLDEN_V2,
    );

    // Structural sanity on the pinned bytes (independent of the AEAD backend).
    assert_eq!(&expected[0..8], &1u64.to_be_bytes(), "counter");
    assert_eq!(&expected[8..20], &IV, "iv");
    assert_eq!(u16::from_be_bytes([expected[36], expected[37]]) as usize, PLAINTEXT.len(), "data_len");
    assert_eq!(&expected[38..40], &[0, 0], "flags: encoded clear, reserved zero");
}

#[test]
fn golden_vector_decrypts_back_to_plaintext() {
    let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);
    receiver.update_peer_key(ExpresslaneKey(KEY)).unwrap();

    let wire = decode_hex(GOLDEN_V2);
    let mut out = vec![0u8; PLAINTEXT.len()];
    let (len, is_encoded) = receiver.decrypt(SESSION_ID, &wire, &mut out).unwrap();
    assert_eq!(&out[..len], PLAINTEXT);
    assert!(!is_encoded);
}
