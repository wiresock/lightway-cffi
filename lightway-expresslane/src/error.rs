//! Errors returned by ExpressLane packet operations.

/// Errors which can occur during ExpressLane packet encrypt/decrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpresslaneError {
    /// Wire packet is shorter than the minimum ExpressLane header.
    InsufficientData,
    /// Caller-provided output buffer is too small.
    BufferTooSmall,
    /// AEAD authentication failed, or the packet is otherwise malformed.
    InvalidData,
    /// Wire counter was rejected by the replay window.
    Replayed,
    /// No key is installed for this operation.
    KeyNotSet,
    /// Key material could not be loaded into the cipher.
    InvalidKey,
}

impl std::fmt::Display for ExpresslaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::InsufficientData => "insufficient data",
            Self::BufferTooSmall => "output buffer too small",
            Self::InvalidData => "invalid express data",
            Self::Replayed => "replayed express data packet",
            Self::KeyNotSet => "key not set",
            Self::InvalidKey => "invalid key",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ExpresslaneError {}

/// Result type for ExpressLane packet operations.
pub type ExpresslaneResult<T> = Result<T, ExpresslaneError>;
