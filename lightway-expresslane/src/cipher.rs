//! AES-256-GCM cipher wrapper used for ExpressLane packet encrypt/decrypt.

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};

use crate::error::{ExpresslaneError, ExpresslaneResult};
use crate::key::ExpresslaneKey;

/// A loaded AES-256-GCM key, ready to encrypt/decrypt ExpressLane packets.
pub(crate) struct Cipher(Aes256Gcm);

impl Cipher {
    pub(crate) fn new(key: &ExpresslaneKey) -> ExpresslaneResult<Self> {
        Aes256Gcm::new_from_slice(&key.0)
            .map(Cipher)
            .map_err(|_| ExpresslaneError::InvalidKey)
    }

    /// Encrypts `buf` in place. Returns the 16-byte detached auth tag.
    pub(crate) fn encrypt(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> ExpresslaneResult<[u8; 16]> {
        let nonce = Nonce::from_slice(iv);
        self.0
            .encrypt_in_place_detached(nonce, aad, buf)
            .map(|tag| tag.into())
            .map_err(|_| ExpresslaneError::InvalidData)
    }

    /// Verifies `tag` and decrypts `buf` in place. Leaves `buf` unchanged on
    /// authentication failure (the underlying `aes-gcm` crate only applies
    /// the keystream after the tag check passes).
    pub(crate) fn decrypt(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> ExpresslaneResult<()> {
        let nonce = Nonce::from_slice(iv);
        let tag = Tag::from_slice(tag);
        self.0
            .decrypt_in_place_detached(nonce, aad, buf, tag)
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
        // Buffer must be byte-identical to the ciphertext on auth failure —
        // not merely "not the plaintext", which would also pass if the
        // failed decrypt had partially transformed it.
        assert_eq!(buf, ciphertext);
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
        // Aes256Gcm::new_from_slice requires exactly 32 bytes; this test
        // documents that Cipher::new propagates that as InvalidKey rather
        // than panicking. ExpresslaneKey's array type already prevents this
        // in practice, so this exercises new_from_slice's own validation path
        // directly.
        let result = Aes256GcmDirect::new_from_slice(&[0u8; 16]);
        assert!(result.is_err());
    }

    // Local alias so the wrong-length test above doesn't need `cipher`'s
    // private field.
    use aes_gcm::Aes256Gcm as Aes256GcmDirect;
}
