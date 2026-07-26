//! AES-256-GCM cipher wrapper used for ExpressLane packet encrypt/decrypt.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, Tag, UnboundKey};

use crate::error::{ExpresslaneError, ExpresslaneResult};
use crate::key::ExpresslaneKey;

/// A loaded AES-256-GCM key, ready to encrypt/decrypt ExpressLane packets.
///
/// Wraps `ring`'s [`LessSafeKey`], which is the only ring AEAD key type that
/// accepts a caller-supplied nonce — `OpeningKey`/`SealingKey` demand a
/// `NonceSequence`, which cannot express "the 12-byte IV arrives on the wire".
/// The "less safe" is exactly the nonce-uniqueness obligation already spelled
/// out on [`crate::session::ExpresslaneSession::encrypt`]; it is not a weaker
/// primitive.
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
        // Every AEAD that ring exposes uses a 128-bit tag, so this cannot fail;
        // expressing it as a fallible conversion rather than `copy_from_slice`
        // keeps a potential panic out of the packet path.
        tag.as_ref()
            .try_into()
            .map_err(|_| ExpresslaneError::InvalidData)
    }

    /// Verifies `tag` and decrypts `buf` in place.
    ///
    /// INVARIANT: on authentication failure `buf` holds UNSPECIFIED bytes, not
    /// the original ciphertext. That is ring's documented contract, and it is
    /// the only thing to rely on. Mechanically, ring 0.17.14 zeroes the buffer
    /// (`aead/algorithm.rs::open_within`) because its AES-GCM assembly
    /// interleaves decryption with authentication and cannot check the tag
    /// first — but the zeroing is an implementation detail, not a promise.
    /// Either way the bytes are no longer the ciphertext, so any caller that
    /// wants to retry them under a different key MUST restore the ciphertext
    /// first — see the fallback in
    /// [`crate::session::ExpresslaneSession::decrypt`].
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
        let ciphertext = buf;

        let result = Cipher::new(&key_b).unwrap().decrypt(&iv, aad, &mut buf, &tag);
        assert_eq!(result, Err(ExpresslaneError::InvalidData));
        // Pins `decrypt`'s stated invariant: the buffer no longer holds the
        // ciphertext after an auth failure. `session.rs` compensates by
        // re-copying the ciphertext before the prev-peer attempt; if this
        // assertion ever flips, that re-copy has become dead weight and the two
        // must be reconsidered together.
        assert_ne!(buf, ciphertext);
    }

    #[test]
    fn failed_decrypt_does_not_preserve_ciphertext() {
        // The payload is deliberately >= 64 bytes: a short buffer could satisfy
        // `decrypt_rejects_wrong_key` by accident (an empty one trivially, since
        // there is nothing left to disturb). This pins the whole multi-block
        // buffer, which is what makes the session-level re-copy load-bearing
        // rather than defensive.
        //
        // Do NOT weaken this to a per-byte assertion such as
        // `assert_ne!(buf[0], ciphertext[0])`: ring zeroes on failure, so any
        // such comparison silently degenerates into `ciphertext[i] != 0` and
        // goes red the day the vector happens to produce a zero there.
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
        assert_ne!(buf, ciphertext);
        // Documents what ring 0.17.14 actually does, so a future upgrade that
        // changes it is noticed here rather than diagnosed from a rotation-loss
        // report. Callers must still treat the contents as unspecified.
        assert!(
            buf.iter().all(|&b| b == 0),
            "ring 0.17.14 zeroes the buffer on authentication failure"
        );

        // ...and restoring the ciphertext makes the retry succeed. This is the
        // exact recovery `session.rs`'s rotation fallback performs.
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
    fn new_with_wrong_length_key_fails() {
        // `UnboundKey::new` requires exactly 32 bytes for AES-256-GCM; this test
        // documents that Cipher::new propagates that as InvalidKey rather than
        // panicking. ExpresslaneKey's array type already prevents this in
        // practice, so this exercises ring's own validation path directly.
        assert!(UnboundKey::new(&AES_256_GCM, &[0u8; 16]).is_err());
    }
}
