//! ExpressLane wire-format version, controlling AAD layout.

/// ExpressLane wire-format version. Controls whether the AEAD associated
/// data includes the flags byte (`Version2`) or not (`Version1`).
#[repr(u8)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Copy, Clone, Default)]
pub enum ExpresslaneVersion {
    /// Not yet negotiated / not recognised by this build.
    #[default]
    Unknown = 0,
    /// Initial ExpressLane wire format (AAD omits the flags byte).
    Version1 = 1,
    /// Same wire layout as V1, but the flags byte is bound into the AEAD AAD.
    Version2 = 2,
}

impl From<u8> for ExpresslaneVersion {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Version1,
            2 => Self::Version2,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u8_known_values() {
        assert_eq!(ExpresslaneVersion::from(1), ExpresslaneVersion::Version1);
        assert_eq!(ExpresslaneVersion::from(2), ExpresslaneVersion::Version2);
    }

    #[test]
    fn from_u8_unknown_values_fall_back_to_unknown() {
        assert_eq!(ExpresslaneVersion::from(0), ExpresslaneVersion::Unknown);
        assert_eq!(ExpresslaneVersion::from(3), ExpresslaneVersion::Unknown);
        assert_eq!(ExpresslaneVersion::from(255), ExpresslaneVersion::Unknown);
    }

    #[test]
    fn default_is_unknown() {
        assert_eq!(ExpresslaneVersion::default(), ExpresslaneVersion::Unknown);
    }

    #[test]
    fn ordering_matches_wire_value() {
        assert!(ExpresslaneVersion::Version2 >= ExpresslaneVersion::Version1);
        assert!(ExpresslaneVersion::Version1 >= ExpresslaneVersion::Unknown);
    }
}
