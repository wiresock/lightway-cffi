//! ExpressLane symmetric key material.

/// Size in bytes of an ExpressLane AES-256-GCM key.
pub const EXPRESSLANE_KEY_SIZE: usize = 32;

/// An ExpressLane AES-256-GCM key.
///
/// `Debug` is deliberately redacted so key material never lands in logs; the
/// expanded key schedule held by the loaded [`crate::cipher::Cipher`] is
/// zeroized on drop via `aes-gcm`'s `zeroize` feature.
#[derive(PartialEq, Eq, Clone, Copy, Default)]
pub struct ExpresslaneKey(pub [u8; EXPRESSLANE_KEY_SIZE]);

impl ExpresslaneKey {
    /// Invalid/unset key sentinel (all-zero).
    pub const INVALID: Self = ExpresslaneKey([0; EXPRESSLANE_KEY_SIZE]);

    /// Returns true if this key is the all-zero `INVALID` sentinel.
    pub fn is_invalid(&self) -> bool {
        *self == Self::INVALID
    }
}

impl std::fmt::Debug for ExpresslaneKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key bytes; distinguish only the all-zero sentinel.
        if self.is_invalid() {
            f.write_str("ExpresslaneKey(INVALID)")
        } else {
            f.write_str("ExpresslaneKey(<redacted>)")
        }
    }
}

impl From<[u8; EXPRESSLANE_KEY_SIZE]> for ExpresslaneKey {
    fn from(value: [u8; EXPRESSLANE_KEY_SIZE]) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_key_is_all_zero() {
        let key = ExpresslaneKey::INVALID;
        assert_eq!(key.0, [0u8; EXPRESSLANE_KEY_SIZE]);
        assert!(key.is_invalid());
    }

    #[test]
    fn nonzero_key_is_not_invalid() {
        let key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        assert!(!key.is_invalid());
    }

    #[test]
    fn from_array() {
        let bytes = [7u8; EXPRESSLANE_KEY_SIZE];
        let key: ExpresslaneKey = bytes.into();
        assert_eq!(key.0, bytes);
    }

    #[test]
    fn default_is_invalid() {
        assert!(ExpresslaneKey::default().is_invalid());
    }
}
