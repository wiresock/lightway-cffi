//! Pure-Rust ExpressLane data-packet encrypt/decrypt primitives.
//!
//! Reimplements the ExpressLane data-packet wire protocol (same format,
//! same 4-key rotation, same replay window) independently of
//! `lightway-core`, using the pure-Rust `aes-gcm` crate instead of
//! wolfssl. See `docs/superpowers/specs/2026-07-16-expresslane-data-cffi-design.md`
//! in this repo for the full design.
