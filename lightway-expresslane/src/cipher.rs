//! AES-256-GCM cipher wrapper used for ExpressLane packet encrypt/decrypt.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, Tag, UnboundKey};

use crate::error::{ExpresslaneError, ExpresslaneResult};
use crate::key::ExpresslaneKey;

/// A loaded AES-256-GCM key, ready to encrypt/decrypt ExpressLane packets.
///
/// Wraps `ring`'s [`LessSafeKey`], which is the only ring AEAD key type that
/// accepts a caller-supplied nonce — `OpeningKey`/`SealingKey` demand a
/// `NonceSequence`, which cannot express "the 12-byte IV arrives on the wire".
/// The "less safe" is API-level, not primitive-level — the AEAD is the same
/// AES-256-GCM. What the type gives up is ring's nonce-sequence enforcement
/// (the obligation that replaces it is spelled out on
/// [`crate::session::ExpresslaneSession::encrypt`]) and its seal/open role
/// separation, since one `LessSafeKey` does both. `Cipher` inherits the second
/// point: nothing type-level stops a peer (receive) cipher from encrypting.
///
/// The key schedule is expanded once here, so the per-packet path does no key
/// setup.
pub(crate) struct Cipher(LessSafeKey);

impl Cipher {
    pub(crate) fn new(key: &ExpresslaneKey) -> ExpresslaneResult<Self> {
        // Unreachable in practice — `ExpresslaneKey.0` is `[u8; 32]` and
        // `AES_256_GCM.key_len()` is 32 — but the length check is ring's only
        // documented failure here, so map it rather than unwrap it.
        UnboundKey::new(&AES_256_GCM, &key.0)
            .map(|unbound| Cipher(LessSafeKey::new(unbound)))
            .map_err(|_| ExpresslaneError::InvalidKey)
    }

    /// Encrypts `buf` in place. Returns the 16-byte detached auth tag.
    pub(crate) fn encrypt(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> ExpresslaneResult<[u8; 16]> {
        let tag = self
            .0
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*iv), Aad::from(aad), buf)
            .map_err(|_| ExpresslaneError::InvalidData)?;
        // AES-256-GCM's tag is 128 bits by definition, and ring caps every tag
        // it produces at the public `MAX_TAG_LEN` (16), so this cannot fail.
        // (ring exposes no per-algorithm constant — only `MAX_TAG_LEN` and a
        // runtime `Algorithm::tag_len()` — so the narrow fact is the one to
        // lean on, not "every ring AEAD tags 16 bytes".) Expressing it as a
        // fallible conversion rather than `copy_from_slice` keeps a potential
        // panic out of the packet path regardless.
        tag.as_ref()
            .try_into()
            .map_err(|_| ExpresslaneError::InvalidData)
    }

    /// Verifies `tag` and decrypts `buf` in place.
    ///
    /// CONTRACT: on ANY `Err` return `buf` holds UNSPECIFIED bytes. ring's
    /// wording is that `in_out` "may have been overwritten in an unspecified
    /// way" — "may", so unspecified includes UNCHANGED. Note the scope is every
    /// error, not just a tag mismatch; this method maps all of ring's error
    /// exits to `InvalidData`.
    ///
    /// Two consequences, and neither may be dropped: `buf` MUST NOT be assumed
    /// to still hold the ciphertext, so a caller wanting to retry these bytes
    /// under a different key MUST restore the ciphertext first (see the fallback
    /// in [`crate::session::ExpresslaneSession::decrypt`]); and `buf` MUST NOT
    /// be assumed to have been destroyed either, so a caller that must not leak
    /// them MUST scrub explicitly.
    ///
    /// VERSION-SPECIFIC OBSERVATION, NOT PART OF THE CONTRACT: ring 0.17.14
    /// zeroes the plaintext region on tag mismatch specifically
    /// (`aead/algorithm.rs`, `Algorithm::open_within`). ring's own comment there
    /// gives the reason, and it is not AES-GCM-specific: checking the tag before
    /// decrypting would be safest, but some `open` implementations interleave
    /// authentication with decryption for performance, so the plaintext already
    /// exists by the time the tags are compared. Do not read that as "the tag
    /// cannot be checked first" — ring frames it as a performance choice.
    /// Only ONE of the other error exits is local to `open_within` (the
    /// `src`-range check) and demonstrably leaves the buffer untouched; the rest
    /// propagate out of `aead::aes_gcm::open`, which has an in-loop exit sitting
    /// *after* earlier chunks were decrypted in place, unreachable only because
    /// this call site passes `0..`. So "untouched on the other exits" is a
    /// property of our call, not of ring — which is why the CONTRACT above is
    /// stated over every `Err`. Pinned by
    /// `ring_0_17_14_zeroes_the_buffer_on_tag_mismatch` below so an upgrade that
    /// changes it is noticed; nothing may depend on it.
    pub(crate) fn decrypt(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> ExpresslaneResult<()> {
        self.0
            .open_in_place_separate_tag(
                Nonce::assume_unique_for_key(*iv),
                Aad::from(aad),
                Tag::from(*tag),
                buf,
                // The whole buffer is ciphertext: decrypt in place, no shift.
                0..,
            )
            .map(|_| ())
            .map_err(|_| ExpresslaneError::InvalidData)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = ExpresslaneKey([42u8; crate::key::EXPRESSLANE_KEY_SIZE]);
        let cipher = Cipher::new(&key).unwrap();
        let iv = [7u8; 12];
        let aad = b"session-id-and-counter";

        let mut buf = *b"Hello, ExpressLane!";
        let tag = cipher.encrypt(&iv, aad, &mut buf).unwrap();
        assert_ne!(&buf[..], b"Hello, ExpressLane!");

        cipher.decrypt(&iv, aad, &mut buf, &tag).unwrap();
        assert_eq!(&buf[..], b"Hello, ExpressLane!");
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let key_a = ExpresslaneKey([1u8; crate::key::EXPRESSLANE_KEY_SIZE]);
        let key_b = ExpresslaneKey([2u8; crate::key::EXPRESSLANE_KEY_SIZE]);
        let iv = [7u8; 12];
        let aad = b"aad";

        let mut buf = *b"secret payload!!";
        let tag = Cipher::new(&key_a).unwrap().encrypt(&iv, aad, &mut buf).unwrap();

        let result = Cipher::new(&key_b).unwrap().decrypt(&iv, aad, &mut buf, &tag);
        assert_eq!(result, Err(ExpresslaneError::InvalidData));
        // Deliberately asserts nothing about `buf` afterwards: ring promises
        // only "unspecified", so any such assertion would pin one ring version's
        // behaviour under a name about key rejection. That pin lives in
        // `ring_0_17_14_zeroes_the_buffer_on_tag_mismatch` below, on its own.
    }

    #[test]
    fn ring_0_17_14_zeroes_the_buffer_on_tag_mismatch() {
        // VERSION PIN, NOT A CONTRACT TEST. ring guarantees only "unspecified"
        // (which permits "unchanged"); this records what 0.17.14 actually does,
        // so an upgrade that changes it is noticed here rather than diagnosed
        // from a rotation-loss report. If a ring upgrade turns this red that is
        // NOT a production bug: `session.rs` re-copies the ciphertext before
        // every attempt and scrubs on the drop path, so it is correct under
        // either behaviour. Update the pin, do not "fix" the caller.
        //
        // A multi-block payload (>= 64 bytes), so the pin covers the whole
        // buffer rather than a single AES block: a future wipe narrowed to one
        // block fails here instead of passing unnoticed.
        //
        // Do NOT weaken the check below to a comparison against the ciphertext
        // (`assert_ne!(buf, ciphertext)`, or worse a per-byte version of it).
        // That is a weaker claim than all-zero, it re-states the same
        // version-specific fact twice, and per-byte it silently degenerates
        // into `ciphertext[i] != 0` — red the day the vector produces a zero
        // there.
        let key_a = ExpresslaneKey([3u8; crate::key::EXPRESSLANE_KEY_SIZE]);
        let key_b = ExpresslaneKey([4u8; crate::key::EXPRESSLANE_KEY_SIZE]);
        let iv = [11u8; 12];
        let aad = b"aad";

        let mut buf = [0xA5u8; 96];
        let tag = Cipher::new(&key_a).unwrap().encrypt(&iv, aad, &mut buf).unwrap();
        let ciphertext = buf;

        assert_eq!(
            Cipher::new(&key_b).unwrap().decrypt(&iv, aad, &mut buf, &tag),
            Err(ExpresslaneError::InvalidData)
        );
        // All-zero is the whole claim; it already implies "not the ciphertext",
        // so no separate `assert_ne!` — one assertion, one claim.
        assert!(
            buf.iter().all(|&b| b == 0),
            "ring 0.17.14 zeroes the buffer on authentication failure"
        );

        // The tail is CONTRACT-level, not version-specific: restoring the
        // ciphertext makes the retry succeed. This is the exact recovery
        // `session.rs`'s rotation fallback performs, and it holds whatever a
        // future ring leaves in the buffer. Keep it when the pin above is
        // eventually retired.
        buf = ciphertext;
        Cipher::new(&key_a).unwrap().decrypt(&iv, aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, [0xA5u8; 96]);
    }

    #[test]
    fn decrypt_rejects_tampered_aad() {
        let key = ExpresslaneKey([9u8; crate::key::EXPRESSLANE_KEY_SIZE]);
        let cipher = Cipher::new(&key).unwrap();
        let iv = [1u8; 12];

        let mut buf = *b"payload!";
        let tag = cipher.encrypt(&iv, b"aad-v1", &mut buf).unwrap();

        let result = cipher.decrypt(&iv, b"aad-v2", &mut buf, &tag);
        assert_eq!(result, Err(ExpresslaneError::InvalidData));
    }

    #[test]
    fn ring_rejects_wrong_length_aes_256_key() {
        // `Cipher::new` maps ring's only documented `UnboundKey::new` failure
        // (key length != algorithm key length) to `InvalidKey`. That arm is
        // unreachable through `Cipher::new` — `ExpresslaneKey.0` is `[u8; 32]` —
        // so this pins only the half that can be reached: ring returns `Err`
        // rather than panicking, which is what makes a `map_err` the right
        // shape there. The mapping itself is not covered by any test, and
        // cannot be without changing `Cipher::new`'s signature.
        assert!(UnboundKey::new(&AES_256_GCM, &[0u8; 16]).is_err());
    }
}
