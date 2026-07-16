# ExpressLane Data-Plane CFFI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two new crates to the `lightway-cffi` repo — `lightway-expresslane` (pure-Rust ExpressLane packet encrypt/decrypt) and `lightway-expresslane-cffi` (its C ABI) — so external code (a Windows usermode service today, a kernel driver later) can encrypt/decrypt individual ExpressLane data packets without the full `Connection`/TLS/IO-loop.

**Architecture:** `lightway-expresslane` reimplements the ExpressLane data-packet wire protocol (same format, same 4-key rotation, same 8192-bit replay window) using the pure-Rust `aes-gcm` crate instead of wolfssl. It splits into a TX half (RwLock/Mutex/AtomicU64-backed, safe for concurrent `encrypt()` from multiple threads) and an RX half (plain fields, exclusive/caller-serialized `decrypt()`). `lightway-expresslane-cffi` is a thin C ABI wrapper, mirroring the existing `lightway-cffi` crate's conventions (`he_*`/`HE_*` naming, `ffi_guard` panic isolation, cbindgen header generation).

**Tech Stack:** Rust (edition 2024), `aes-gcm` 0.10 (RustCrypto), `cbindgen` 0.29, Cargo workspace, `jj` for version control.

## Global Constraints

- No changes to `lightway-core` or the `expressvpn/lightway` repo — this work is entirely additive to the `lightway-cffi` repo (per spec's Non-goals).
- No `Vec`/`Box` crosses the FFI boundary; all buffers are caller-owned (per spec's Conventions).
- Caller supplies the IV on encrypt; the crate has no RNG dependency (per spec's Conventions).
- `encrypt()`/`reserve_counter()`/`update_next_self_key()`/`promote_self_key()`/`packets_sent()` are the TX domain — safe to call concurrently from multiple threads on one session. `decrypt()`/`update_peer_key()`/`has_valid_keys()`/`packets_received()` are the RX domain — caller must serialize (per spec's "Parallel encrypt").
- Panics are caught at every `extern "C"` boundary function and mapped to `HE_EXPRESSLANE_ERR_PANIC` (per spec's Conventions).
- Wire format is fixed: `Counter(8) | IV(12) | AuthTag(16) | DataLen(2) | Flags(2) | Ciphertext(DataLen)`, 40 bytes overhead. AAD is `SessionID(8) || Counter(8)` for V1, `SessionID(8) || Counter(8) || Flags(2)` for V2 (per spec).
- The cross-crate live-handshake interop test described in the spec's "Accepted risk" section is explicitly **out of scope for this plan** (descoped per user direction) — it is not one of the tasks below.
- Follow the existing `lightway-cffi` crate's conventions exactly where they apply: `#[unsafe(no_mangle)] pub unsafe extern "C" fn`, `# Safety` doc sections, `ffi_guard`-style panic isolation, `#![warn(missing_docs)]` (every `pub` item needs a doc comment or `cargo clippy -D warnings` in CI fails), null-pointer checks returning an error code rather than dereferencing, raw-integer parameters instead of directly-transmuted enums where an out-of-range C value would otherwise be an invalid discriminant (UB).
- Module layout follows this repo's existing flat-file convention (`foo.rs`, not `foo/mod.rs`).
- Commit with `jj commit -m "<message>"` at the end of each task (this repo is jj-colocated with git).

---

## Task 1: Convert the repo to a Cargo workspace

**Files:**
- Modify: `Cargo.toml:1-24` (repo root)

**Interfaces:**
- Consumes: nothing new.
- Produces: a `[workspace]` table at the repo root, listing only `lightway-expresslane` for now. The existing `lightway-cffi` package becomes the workspace's root member (implicit — a manifest with both `[package]` and `[workspace]` is automatically a member of its own workspace; it does not need to list itself in `members`).

**Note (found during Task 3's execution, corrected here):** an earlier version of this plan listed both `lightway-expresslane` and `lightway-expresslane-cffi` in `members` from this task onward, on the assumption a dangling (not-yet-created) member was harmless. It is not: Cargo must load every listed member's manifest to run *any* command in the workspace, including `cargo test -p <one-crate>` — a single missing member's `Cargo.toml` fails the whole workspace, verified empirically. Since Tasks 3-9 all need working `cargo test -p lightway-expresslane` calls, `lightway-expresslane-cffi` must not be listed until Task 10 actually creates that directory (Task 10 adds it then — see that task's Step 0).

- [ ] **Step 1: Add the `[workspace]` table to the root `Cargo.toml`**

Current file:
```toml
[package]
name = "lightway-cffi"
version = "0.1.0"
edition = "2024"
description = "C ABI shim over lightway-core (Rust) for C/C++ consumers (e.g. kp_pkf_client)."
license = "AGPL-3.0-only"
repository = "https://github.com/expressvpn/lightway-cffi"

[lib]
# cdylib: lightway_cffi.dll + import lib for dynamic linking
# staticlib: lightway_cffi.lib for fully-static embedding
# rlib: allow use as a Rust dep for tests / downstream Rust consumers
crate-type = ["cdylib", "staticlib", "rlib"]

[lints.rust]
unsafe_op_in_unsafe_fn = "deny"
[lints.clippy]
undocumented_unsafe_blocks = "deny"

[dependencies]
bytes = "1.6.0"
lightway-core = { git = "https://github.com/expressvpn/lightway", rev = "4ee75d00406d1fa84f5fdc17e9935a07d77801fe", features = ["postquantum"] }

[build-dependencies]
cbindgen = "0.29"
```

Add a `[workspace]` table right after `[package]`'s closing (before `[lib]`):

```toml
[package]
name = "lightway-cffi"
version = "0.1.0"
edition = "2024"
description = "C ABI shim over lightway-core (Rust) for C/C++ consumers (e.g. kp_pkf_client)."
license = "AGPL-3.0-only"
repository = "https://github.com/expressvpn/lightway-cffi"

[workspace]
members = ["lightway-expresslane"]

[lib]
# cdylib: lightway_cffi.dll + import lib for dynamic linking
# staticlib: lightway_cffi.lib for fully-static embedding
# rlib: allow use as a Rust dep for tests / downstream Rust consumers
crate-type = ["cdylib", "staticlib", "rlib"]

[lints.rust]
unsafe_op_in_unsafe_fn = "deny"
[lints.clippy]
undocumented_unsafe_blocks = "deny"

[dependencies]
bytes = "1.6.0"
lightway-core = { git = "https://github.com/expressvpn/lightway", rev = "4ee75d00406d1fa84f5fdc17e9935a07d77801fe", features = ["postquantum"] }

[build-dependencies]
cbindgen = "0.29"
```

- [ ] **Step 2: Note that the workspace won't resolve until Task 2**

`members` now references `lightway-expresslane/`, which doesn't exist yet —
`cargo build`/`cargo metadata` will fail with "failed to load manifest" until
Task 2 creates it. That's expected; this task only adds the `[workspace]`
table. Task 2's Step 3 is where the workspace is first verified to build.
`lightway-expresslane-cffi` is deliberately NOT listed yet — see the note
above; Task 10 adds it once that directory actually exists.

- [ ] **Step 3: Commit**

```bash
jj commit -m "cffi: convert repo to a Cargo workspace"
```

---

## Task 2: Scaffold the `lightway-expresslane` crate

**Files:**
- Create: `lightway-expresslane/Cargo.toml`
- Create: `lightway-expresslane/src/lib.rs`

**Interfaces:**
- Consumes: the `[workspace] members = ["lightway-expresslane"]` list added in Task 1.
- Produces: an empty, buildable `lightway-expresslane` rlib crate that later tasks add modules to.

- [ ] **Step 1: Create `lightway-expresslane/Cargo.toml`**

```toml
[package]
name = "lightway-expresslane"
version = "0.1.0"
edition = "2024"
description = "Pure-Rust ExpressLane data-packet encrypt/decrypt primitives, independent of lightway-core."
license = "AGPL-3.0-only"
repository = "https://github.com/expressvpn/lightway-cffi"

[lib]
crate-type = ["rlib"]

[lints.rust]
unsafe_op_in_unsafe_fn = "deny"
missing_docs = "warn"

[dependencies]
aes-gcm = { version = "0.10", default-features = false, features = ["aes"] }
```

- [ ] **Step 2: Create `lightway-expresslane/src/lib.rs`**

```rust
//! Pure-Rust ExpressLane data-packet encrypt/decrypt primitives.
//!
//! Reimplements the ExpressLane data-packet wire protocol (same format,
//! same 4-key rotation, same replay window) independently of
//! `lightway-core`, using the pure-Rust `aes-gcm` crate instead of
//! wolfssl. See `docs/superpowers/specs/2026-07-16-expresslane-data-cffi-design.md`
//! in this repo for the full design.
```

- [ ] **Step 3: Verify the workspace resolves and builds**

Run: `cargo build -p lightway-expresslane`
Expected: builds successfully (empty crate, no warnings).

Run: `cargo build`
Expected: builds both `lightway-cffi` and `lightway-expresslane` successfully — `members` currently lists only `lightway-expresslane` (per Task 1's corrected sequencing), so there is no dangling member to work around here.

- [ ] **Step 4: Commit**

```bash
jj commit -m "expresslane: scaffold lightway-expresslane crate"
```

---

## Task 3: `ExpresslaneKey`

**Files:**
- Create: `lightway-expresslane/src/key.rs`
- Modify: `lightway-expresslane/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `pub struct ExpresslaneKey(pub [u8; 32])`, `pub const EXPRESSLANE_KEY_SIZE: usize = 32`, used by every later task that handles key material.

- [ ] **Step 1: Write the failing test**

Create `lightway-expresslane/src/key.rs`:

```rust
//! ExpressLane symmetric key material.

/// Size in bytes of an ExpressLane AES-256-GCM key.
pub const EXPRESSLANE_KEY_SIZE: usize = 32;

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
```

Add to `lightway-expresslane/src/lib.rs`:

```rust
mod key;

pub use key::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p lightway-expresslane key::`
Expected: FAIL to compile — `ExpresslaneKey` is not defined.

- [ ] **Step 3: Implement `ExpresslaneKey`**

Add to `lightway-expresslane/src/key.rs` (above the `#[cfg(test)]` module):

```rust
/// An ExpressLane AES-256-GCM key.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
pub struct ExpresslaneKey(pub [u8; EXPRESSLANE_KEY_SIZE]);

impl ExpresslaneKey {
    /// Invalid/unset key sentinel (all-zero).
    pub const INVALID: Self = ExpresslaneKey([0; EXPRESSLANE_KEY_SIZE]);

    /// Returns true if this key is the all-zero `INVALID` sentinel.
    pub fn is_invalid(&self) -> bool {
        *self == Self::INVALID
    }
}

impl From<[u8; EXPRESSLANE_KEY_SIZE]> for ExpresslaneKey {
    fn from(value: [u8; EXPRESSLANE_KEY_SIZE]) -> Self {
        Self(value)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p lightway-expresslane key::`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
jj commit -m "expresslane: add ExpresslaneKey"
```

---

## Task 4: `ExpresslaneVersion`

**Files:**
- Create: `lightway-expresslane/src/version.rs`
- Modify: `lightway-expresslane/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `pub enum ExpresslaneVersion { Unknown = 0, Version1 = 1, Version2 = 2 }`, used by the AAD-layout logic in Task 7/8's `build_aad`.

- [ ] **Step 1: Write the failing test**

Create `lightway-expresslane/src/version.rs`:

```rust
//! ExpressLane wire-format version, controlling AAD layout.

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
```

Add to `lightway-expresslane/src/lib.rs`:

```rust
mod version;

pub use version::ExpresslaneVersion;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p lightway-expresslane version::`
Expected: FAIL to compile — `ExpresslaneVersion` is not defined.

- [ ] **Step 3: Implement `ExpresslaneVersion`**

Add to `lightway-expresslane/src/version.rs` (above the `#[cfg(test)]` module):

```rust
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p lightway-expresslane version::`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
jj commit -m "expresslane: add ExpresslaneVersion"
```

---

## Task 5: `ExpresslaneError` and the `Cipher` AES-256-GCM wrapper

**Files:**
- Create: `lightway-expresslane/src/error.rs`
- Create: `lightway-expresslane/src/cipher.rs`
- Modify: `lightway-expresslane/src/lib.rs`

**Interfaces:**
- Consumes: `ExpresslaneKey` (Task 3).
- Produces: `pub enum ExpresslaneError { InsufficientData, BufferTooSmall, InvalidData, Replayed, KeyNotSet, InvalidKey }`, `pub type ExpresslaneResult<T>`, and `pub(crate) struct Cipher` with `new`, `encrypt`, `decrypt` — the AEAD primitive every later task builds on.

- [ ] **Step 1: Write the failing test**

Create `lightway-expresslane/src/error.rs`:

```rust
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
```

Create `lightway-expresslane/src/cipher.rs`:

```rust
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
        let plaintext = buf;
        let tag = Cipher::new(&key_a).unwrap().encrypt(&iv, aad, &mut buf).unwrap();

        let result = Cipher::new(&key_b).unwrap().decrypt(&iv, aad, &mut buf, &tag);
        assert_eq!(result, Err(ExpresslaneError::InvalidData));
        // Buffer must be untouched on auth failure (still ciphertext, not plaintext).
        assert_ne!(&buf[..], &plaintext[..]);
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
```

Add to `lightway-expresslane/src/lib.rs`:

```rust
mod cipher;
mod error;

pub use error::{ExpresslaneError, ExpresslaneResult};
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p lightway-expresslane`
Expected: FAIL to compile — `aes_gcm` crate items not yet resolvable in context / `Cipher` not wired up. (If it happens to compile because the crate builds top-down fine, this step still confirms current baseline; proceed to Step 3 either way and re-run.)

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test -p lightway-expresslane cipher::`
Expected: 4 passed.

Run: `cargo test -p lightway-expresslane error::`
Expected: 0 tests (no `#[cfg(test)]` module in `error.rs` — that's expected, the type is exercised via `cipher::tests`).

- [ ] **Step 4: Commit**

```bash
jj commit -m "expresslane: add ExpresslaneError and AES-256-GCM Cipher wrapper"
```

---

## Task 6: `ReplayWindow`

**Files:**
- Create: `lightway-expresslane/src/replay_window.rs`
- Modify: `lightway-expresslane/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `pub(crate) struct ReplayWindow` with `would_reject(&self, u64) -> bool`, `commit(&mut self, u64) -> bool`, `packets_received(&self) -> u64`. Ported verbatim (same algorithm, same tests) from `lightway-core/src/wire/expresslane_data.rs`'s `ReplayWindow` — this crate reimplements it independently rather than sharing code, per the design's "Accepted risk" section.

- [ ] **Step 1: Write the failing tests**

Create `lightway-expresslane/src/replay_window.rs`:

```rust
//! Sliding-window replay protection for received ExpressLane packets.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_first_packet() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert_eq!(window.packets_received(), 1);
    }

    #[test]
    fn detects_exact_replay() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(!window.commit(100));
        assert_eq!(window.packets_received(), 1);
    }

    #[test]
    fn accepts_newer_packets() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(window.commit(101));
        assert!(window.commit(102));
        assert_eq!(window.packets_received(), 3);
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(window.commit(105));
        assert!(window.commit(103));
        assert!(window.commit(102));
        assert_eq!(window.packets_received(), 4);
    }

    #[test]
    fn rejects_replayed_out_of_order_packet() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(window.commit(105));
        assert!(window.commit(103));
        assert!(!window.commit(103));
        assert_eq!(window.packets_received(), 3);
    }

    #[test]
    fn rejects_too_old_packets() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(window.commit(10000)); // advance window past 8192
        // 10000 - 8192 = 1808, so 1808 is the oldest still-in-window counter.
        assert!(!window.commit(100));
        assert!(!window.commit(1808));
        assert!(window.commit(1809));
        assert_eq!(window.packets_received(), 3);
    }

    #[test]
    fn handles_large_jumps() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(window.commit(10000));
        assert!(!window.commit(100));
        assert_eq!(window.packets_received(), 2);
    }

    #[test]
    fn full_scenario() {
        let mut window = ReplayWindow::default();
        for i in 1..=10 {
            assert!(window.commit(i), "failed to accept packet {i}");
        }
        assert!(window.commit(15));
        assert!(window.commit(13));
        assert!(window.commit(11));
        assert!(window.commit(12));
        assert!(window.commit(14));
        assert!(!window.commit(10));
        assert!(!window.commit(13));
        assert!(!window.commit(15));
        assert!(window.commit(16));
        assert!(window.commit(17));
        assert_eq!(window.packets_received(), 17);
    }

    #[test]
    fn would_reject_is_non_mutating() {
        let mut window = ReplayWindow::default();
        assert!(!window.would_reject(100));
        assert_eq!(window.packets_received(), 0);

        assert!(window.commit(100));
        assert!(window.would_reject(100));
        assert_eq!(window.packets_received(), 1);

        assert!(!window.would_reject(u64::MAX));
        assert_eq!(window.packets_received(), 1);
    }

    #[test]
    fn window_size_is_8192() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(0));
        assert!(window.commit(8192));
        // 8192 - 0 = 8192 == WINDOW_SIZE, exactly out of window.
        assert!(!window.commit(0));
        assert!(window.commit(1));
    }
}
```

Add to `lightway-expresslane/src/lib.rs`:

```rust
mod replay_window;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p lightway-expresslane replay_window::`
Expected: FAIL to compile — `ReplayWindow` is not defined.

- [ ] **Step 3: Implement `ReplayWindow`**

Add to `lightway-expresslane/src/replay_window.rs` (above the `#[cfg(test)]` module):

```rust
/// Tracks received packet counters to detect and prevent replay attacks
/// while tolerating out-of-order UDP delivery.
///
/// Uses an 8192-bit bitmap (128 × u64) to tolerate significant packet
/// reordering under high-throughput conditions.
#[derive(Debug, Clone)]
pub(crate) struct ReplayWindow {
    max_counter: u64,
    bitmap: [u64; Self::NUM_BLOCKS],
    packets_received: u64,
    initialized: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            max_counter: 0,
            bitmap: [0; Self::NUM_BLOCKS],
            packets_received: 0,
            initialized: false,
        }
    }
}

impl ReplayWindow {
    const NUM_BLOCKS: usize = 128;
    const WINDOW_SIZE: u64 = (Self::NUM_BLOCKS as u64) * 64;

    fn set_bit(&mut self, position: u64) {
        let block = (position / 64) as usize;
        let bit = position % 64;
        if block < Self::NUM_BLOCKS {
            self.bitmap[block] |= 1u64 << bit;
        }
    }

    fn test_bit(&self, position: u64) -> bool {
        let block = (position / 64) as usize;
        let bit = position % 64;
        if block < Self::NUM_BLOCKS {
            (self.bitmap[block] & (1u64 << bit)) != 0
        } else {
            false
        }
    }

    fn shift_left(&mut self, count: u64) {
        if count >= Self::WINDOW_SIZE {
            self.bitmap = [0; Self::NUM_BLOCKS];
            return;
        }

        let block_shift = (count / 64) as usize;
        let bit_shift = (count % 64) as u32;

        if bit_shift == 0 {
            for i in (block_shift..Self::NUM_BLOCKS).rev() {
                self.bitmap[i] = self.bitmap[i - block_shift];
            }
        } else {
            for i in (0..Self::NUM_BLOCKS).rev() {
                let lower = if i >= block_shift {
                    self.bitmap[i - block_shift] << bit_shift
                } else {
                    0
                };
                let upper = if i > block_shift {
                    self.bitmap[i - block_shift - 1] >> (64 - bit_shift)
                } else {
                    0
                };
                self.bitmap[i] = lower | upper;
            }
        }

        for i in 0..block_shift.min(Self::NUM_BLOCKS) {
            self.bitmap[i] = 0;
        }
    }

    /// Non-mutating pre-check, to short-circuit obvious garbage before
    /// paying the AEAD cost. Returns true iff the packet should be
    /// rejected. Callers MUST NOT treat a `false` result as final
    /// acceptance — [`Self::commit`] must still run after AEAD
    /// verification succeeds.
    pub(crate) fn would_reject(&self, wire_counter: u64) -> bool {
        if !self.initialized {
            return false;
        }
        if wire_counter > self.max_counter {
            return false;
        }
        let age = self.max_counter - wire_counter;
        if age >= Self::WINDOW_SIZE {
            return true;
        }
        self.test_bit(age)
    }

    /// Commit a successfully-deprotected wire counter into the window.
    /// MUST only be called after AEAD verification succeeds. Returns true
    /// if accepted; false if the counter is a replay or too old (state
    /// unchanged in that case).
    pub(crate) fn commit(&mut self, wire_counter: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.max_counter = wire_counter;
            self.bitmap[0] = 1;
            self.packets_received += 1;
            return true;
        }

        if wire_counter > self.max_counter {
            let diff = wire_counter - self.max_counter;
            self.shift_left(diff);
            self.bitmap[0] |= 1;
            self.max_counter = wire_counter;
            self.packets_received += 1;
            return true;
        }

        let age = self.max_counter - wire_counter;
        if age < Self::WINDOW_SIZE {
            if self.test_bit(age) {
                return false;
            }
            self.set_bit(age);
            self.packets_received += 1;
            return true;
        }

        false
    }

    /// Total number of packets successfully committed.
    pub(crate) fn packets_received(&self) -> u64 {
        self.packets_received
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p lightway-expresslane replay_window::`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
jj commit -m "expresslane: add ReplayWindow"
```

---

## Task 7: `ExpresslaneSession` — TX domain (encrypt, key rotation)

**Files:**
- Create: `lightway-expresslane/src/session.rs`
- Modify: `lightway-expresslane/src/lib.rs`

**Interfaces:**
- Consumes: `ExpresslaneKey`/`EXPRESSLANE_KEY_SIZE` (Task 3), `ExpresslaneVersion` (Task 4), `ExpresslaneError`/`ExpresslaneResult` (Task 5), `Cipher` (Task 5).
- Produces: `pub struct ExpresslaneSession` with `WIRE_OVERHEAD: usize = 40`, `new(ExpresslaneVersion) -> Self`, `reserve_counter(&self) -> u64`, `update_next_self_key(&self, ExpresslaneKey) -> ExpresslaneResult<()>`, `promote_self_key(&self)`, `packets_sent(&self) -> u64`, `encrypt(&self, counter: u64, session_id: [u8;8], plain_text: &[u8], iv: [u8;12], is_encoded: bool, out: &mut [u8]) -> ExpresslaneResult<usize>`. RX-domain fields are declared here too (used by Task 8) but not yet exercised.

- [ ] **Step 1: Write the failing tests**

Create `lightway-expresslane/src/session.rs`:

```rust
//! ExpressLane packet session: key rotation state, replay window, and
//! encrypt/decrypt.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use crate::cipher::Cipher;
use crate::error::{ExpresslaneError, ExpresslaneResult};
use crate::key::ExpresslaneKey;
use crate::replay_window::ReplayWindow;
use crate::version::ExpresslaneVersion;

/// Build the AEAD associated data for an ExpressLane data packet.
/// Returns a fixed-size buffer and the number of significant bytes.
fn build_aad(
    version: ExpresslaneVersion,
    session_id: [u8; 8],
    counter: u64,
    encoded: bool,
) -> ([u8; 18], usize) {
    let mut buf = [0u8; 18];
    buf[..8].copy_from_slice(&session_id);
    buf[8..16].copy_from_slice(&counter.to_be_bytes());
    if version >= ExpresslaneVersion::Version2 {
        let flags: u16 = if encoded { 0x8000 } else { 0 };
        buf[16..].copy_from_slice(&flags.to_be_bytes());
        (buf, 18)
    } else {
        (buf, 16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::EXPRESSLANE_KEY_SIZE;

    #[test]
    fn reserve_counter_starts_at_one_and_increments() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        assert_eq!(session.reserve_counter(), 1);
        assert_eq!(session.reserve_counter(), 2);
        assert_eq!(session.reserve_counter(), 3);
    }

    #[test]
    fn encrypt_without_key_returns_key_not_set() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + 4];
        let result = session.encrypt(1, [1u8; 8], b"test", [0u8; 12], false, &mut out);
        assert_eq!(result, Err(ExpresslaneError::KeyNotSet));
    }

    #[test]
    fn update_next_self_key_then_promote_enables_encrypt() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        session.update_next_self_key(key).unwrap();
        session.promote_self_key();

        let plain_text = b"test data";
        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = session
            .encrypt(1, [1u8; 8], plain_text, [0u8; 12], false, &mut out)
            .unwrap();
        assert_eq!(n, out.len());
    }

    #[test]
    fn promote_without_staged_key_is_a_no_op() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        session.promote_self_key(); // no next_self staged - must not panic
        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + 4];
        let result = session.encrypt(1, [1u8; 8], b"test", [0u8; 12], false, &mut out);
        assert_eq!(result, Err(ExpresslaneError::KeyNotSet));
    }

    #[test]
    fn encrypt_writes_expected_wire_layout() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        session.update_next_self_key(key).unwrap();
        session.promote_self_key();

        let session_id = [1u8; 8];
        let plain_text = b"test data";
        let iv = [9u8; 12];
        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = session
            .encrypt(5, session_id, plain_text, iv, false, &mut out)
            .unwrap();
        out.truncate(n);

        assert_eq!(u64::from_be_bytes(out[0..8].try_into().unwrap()), 5);
        assert_eq!(&out[8..20], &iv[..]);
        assert_eq!(
            u16::from_be_bytes(out[36..38].try_into().unwrap()) as usize,
            plain_text.len()
        );
        assert_eq!(out.len(), ExpresslaneSession::WIRE_OVERHEAD + plain_text.len());
    }

    #[test]
    fn encrypt_rejects_buffer_too_small() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        session.update_next_self_key(key).unwrap();
        session.promote_self_key();

        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD]; // too small for any payload
        let result = session.encrypt(1, [1u8; 8], b"x", [0u8; 12], false, &mut out);
        assert_eq!(result, Err(ExpresslaneError::BufferTooSmall));
    }

    #[test]
    fn packets_sent_counts_successful_encrypts_only() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        session.update_next_self_key(key).unwrap();
        session.promote_self_key();

        assert_eq!(session.packets_sent(), 0);
        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + 4];
        session.encrypt(1, [1u8; 8], b"test", [0u8; 12], false, &mut out).unwrap();
        session.encrypt(2, [1u8; 8], b"test", [0u8; 12], false, &mut out).unwrap();
        assert_eq!(session.packets_sent(), 2);

        // A failed encrypt (buffer too small) must not bump the counter.
        let mut too_small = vec![0u8; 4];
        let _ = session.encrypt(3, [1u8; 8], b"test", [0u8; 12], false, &mut too_small);
        assert_eq!(session.packets_sent(), 2);
    }

    #[test]
    fn wire_counter_increments_independently_of_encrypt_calls() {
        // reserve_counter and encrypt's `counter` param are decoupled by
        // design - callers may reserve without encrypting, or supply their
        // own scheme entirely. Verify encrypt() writes exactly the counter
        // it was given, not an internally-tracked one.
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        session.update_next_self_key(key).unwrap();
        session.promote_self_key();

        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + 4];
        session.encrypt(1000, [1u8; 8], b"test", [0u8; 12], false, &mut out).unwrap();
        assert_eq!(u64::from_be_bytes(out[0..8].try_into().unwrap()), 1000);
    }
}
```

Add to `lightway-expresslane/src/lib.rs`:

```rust
mod session;

pub use session::ExpresslaneSession;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p lightway-expresslane session::`
Expected: FAIL to compile — `ExpresslaneSession` is not defined.

- [ ] **Step 3: Implement `ExpresslaneSession`'s TX domain**

Add to `lightway-expresslane/src/session.rs`, after `build_aad` and before `#[cfg(test)]`:

```rust
/// An ExpressLane packet-crypto session: key rotation state, replay
/// window, and encrypt/decrypt.
///
/// Splits into two independently-synchronized halves — see
/// `docs/superpowers/specs/2026-07-16-expresslane-data-cffi-design.md`'s
/// "Parallel encrypt" section in the `lightway-cffi` repo for the full
/// rationale:
///
/// - TX state (`current_self`, `next_self`, counters): safe to call
///   concurrently from multiple threads on the same session.
/// - RX state (`current_peer`, `prev_peer`, `replay_window`): exclusive
///   access only — callers must externally serialize `decrypt`,
///   `update_peer_key`, `has_valid_keys`, `packets_received`.
pub struct ExpresslaneSession {
    version: ExpresslaneVersion,

    current_self: RwLock<Option<Cipher>>,
    next_self: Mutex<Option<Cipher>>,
    next_counter: AtomicU64,
    packets_sent: AtomicU64,

    current_peer: Option<Cipher>,
    prev_peer: Option<Cipher>,
    replay_window: ReplayWindow,
}

impl ExpresslaneSession {
    /// Wire overhead in bytes: 8 (counter) + 12 (iv) + 16 (tag) + 2
    /// (data length) + 2 (flags).
    pub const WIRE_OVERHEAD: usize = 40;

    /// Create a new session with no keys installed.
    pub fn new(version: ExpresslaneVersion) -> Self {
        Self {
            version,
            current_self: RwLock::new(None),
            next_self: Mutex::new(None),
            next_counter: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            current_peer: None,
            prev_peer: None,
            replay_window: ReplayWindow::default(),
        }
    }

    // ---- TX domain: safe to call concurrently from multiple threads. ----

    /// Reserve a wire counter value guaranteed unique for this session
    /// (lock-free atomic increment). Use the returned value as `counter`
    /// in the next `encrypt()` call, unless the caller has its own
    /// uniqueness guarantee across every thread encrypting on this
    /// session.
    pub fn reserve_counter(&self) -> u64 {
        // Matches upstream lightway-core: first packet is counter 1, not 0.
        self.next_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Stage a new "next self" key. Call `promote_self_key` once the peer
    /// has acknowledged the rotation to make it the active send key.
    pub fn update_next_self_key(&self, key: ExpresslaneKey) -> ExpresslaneResult<()> {
        let cipher = Cipher::new(&key)?;
        *self.next_self.lock().unwrap_or_else(|e| e.into_inner()) = Some(cipher);
        Ok(())
    }

    /// Promote the staged "next self" key to the active send key. A no-op
    /// if no key is staged.
    pub fn promote_self_key(&self) {
        let mut next = self.next_self.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cipher) = next.take() {
            *self.current_self.write().unwrap_or_else(|e| e.into_inner()) = Some(cipher);
        }
    }

    /// Total number of packets successfully encrypted so far.
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Encrypt `plain_text` into ExpressLane wire format, writing into
    /// `out`. `out` must have capacity for at least
    /// `WIRE_OVERHEAD + plain_text.len()` bytes. `counter` must be unique
    /// for this session — see `reserve_counter`. Returns the number of
    /// bytes written to `out`.
    pub fn encrypt(
        &self,
        counter: u64,
        session_id: [u8; 8],
        plain_text: &[u8],
        iv: [u8; 12],
        is_encoded: bool,
        out: &mut [u8],
    ) -> ExpresslaneResult<usize> {
        let needed = Self::WIRE_OVERHEAD + plain_text.len();
        if out.len() < needed {
            return Err(ExpresslaneError::BufferTooSmall);
        }
        if plain_text.len() > u16::MAX as usize {
            return Err(ExpresslaneError::InvalidData);
        }

        let guard = self.current_self.read().unwrap_or_else(|e| e.into_inner());
        let cipher = guard.as_ref().ok_or(ExpresslaneError::KeyNotSet)?;

        let (aad_buf, aad_len) = build_aad(self.version, session_id, counter, is_encoded);

        out[8..20].copy_from_slice(&iv);
        out[40..needed].copy_from_slice(plain_text);
        let tag = cipher.encrypt(&iv, &aad_buf[..aad_len], &mut out[40..needed])?;
        drop(guard);

        out[0..8].copy_from_slice(&counter.to_be_bytes());
        out[20..36].copy_from_slice(&tag);
        out[36..38].copy_from_slice(&(plain_text.len() as u16).to_be_bytes());
        let flags: u16 = if is_encoded { 0x8000 } else { 0 };
        out[38..40].copy_from_slice(&flags.to_be_bytes());

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        Ok(needed)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p lightway-expresslane session::`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
jj commit -m "expresslane: add ExpresslaneSession TX domain (encrypt, key rotation)"
```

---

## Task 8: `ExpresslaneSession` — RX domain (decrypt) and round-trip tests

**Files:**
- Modify: `lightway-expresslane/src/session.rs`

**Interfaces:**
- Consumes: everything from Task 7 (same struct, same file).
- Produces: `update_peer_key(&mut self, ExpresslaneKey) -> ExpresslaneResult<()>`, `has_valid_keys(&mut self) -> bool`, `packets_received(&mut self) -> u64`, `decrypt(&mut self, session_id: [u8;8], wire_packet: &[u8], out: &mut [u8]) -> ExpresslaneResult<(usize, bool)>`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `lightway-expresslane/src/session.rs` (after the existing TX tests):

```rust
    #[test]
    fn round_trip_encryption_decryption() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let plain_text = b"Hello, ExpressLane!";
        let iv = [9u8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, iv, false, &mut wire).unwrap();
        wire.truncate(n);

        let mut out = vec![0u8; plain_text.len()];
        let (len, is_encoded) = receiver.decrypt(session_id, &wire, &mut out).unwrap();
        assert_eq!(&out[..len], plain_text);
        assert!(!is_encoded);
    }

    #[test]
    fn round_trip_with_encoded_flag() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"Encoded payload";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], true, &mut wire).unwrap();
        wire.truncate(n);

        let mut out = vec![0u8; plain_text.len()];
        let (len, is_encoded) = receiver.decrypt(session_id, &wire, &mut out).unwrap();
        assert_eq!(&out[..len], plain_text);
        assert!(is_encoded);
    }

    #[test]
    fn decrypt_without_key_returns_key_not_set() {
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD];
        let mut out = vec![0u8; 4];
        let result = receiver.decrypt([1u8; 8], &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::KeyNotSet));
    }

    #[test]
    fn decrypt_rejects_insufficient_data() {
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD - 1];
        let mut out = vec![0u8; 4];
        let result = receiver.decrypt([1u8; 8], &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::InsufficientData));
    }

    #[test]
    fn decrypt_rejects_replay() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"replay me";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire).unwrap();
        wire.truncate(n);

        let mut out = vec![0u8; plain_text.len()];
        receiver.decrypt(session_id, &wire, &mut out).unwrap();
        let result = receiver.decrypt(session_id, &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::Replayed));
    }

    #[test]
    fn decrypt_falls_back_to_prev_peer_key_during_rotation() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let old_key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        let new_key = ExpresslaneKey([2u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(old_key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(old_key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"in flight during rotation";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire).unwrap();
        wire.truncate(n);

        // Receiver rotates to new_key before this in-flight (old_key-encrypted)
        // packet arrives - it must still decrypt via prev_peer.
        receiver.update_peer_key(new_key).unwrap();

        let mut out = vec![0u8; plain_text.len()];
        let (len, _) = receiver.decrypt(session_id, &wire, &mut out).unwrap();
        assert_eq!(&out[..len], plain_text);
    }

    #[test]
    fn cross_version_v1_to_v2_fails() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version1);
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"v1 to v2";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire).unwrap();
        wire.truncate(n);

        let mut out = vec![0u8; plain_text.len()];
        let result = receiver.decrypt(session_id, &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::InvalidData));
    }

    #[test]
    fn tampered_flags_rejected_by_aead() {
        // On-path attacker flips the encoded flag. AEAD must reject V2
        // packets because the flags field is bound into the auth tag.
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"sensitive payload";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire).unwrap();
        wire.truncate(n);

        assert_eq!(wire[38] & 0x80, 0, "precondition: encoded flag is clear");
        wire[38] |= 0x80;

        let mut out = vec![0u8; plain_text.len()];
        let result = receiver.decrypt(session_id, &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::InvalidData));
    }

    #[test]
    fn forged_packet_does_not_poison_replay_window() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"hello expresslane";

        let mut wire1 = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire1).unwrap();
        wire1.truncate(n);
        let mut out = vec![0u8; plain_text.len()];
        receiver.decrypt(session_id, &wire1, &mut out).unwrap();
        assert_eq!(receiver.packets_received(), 1);

        // Forge a packet with a huge counter and a bogus tag (no key).
        let mut forged = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        forged[0..8].copy_from_slice(&(u64::MAX - 1).to_be_bytes());
        forged[36..38].copy_from_slice(&(plain_text.len() as u16).to_be_bytes());
        let mut out2 = vec![0u8; plain_text.len()];
        let result = receiver.decrypt(session_id, &forged, &mut out2);
        assert_eq!(result, Err(ExpresslaneError::InvalidData));

        // Window state must be untouched by the forgery.
        assert_eq!(receiver.packets_received(), 1);

        // Next valid packet (counter=2) must still be accepted.
        let mut wire2 = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(2, session_id, plain_text, [0u8; 12], false, &mut wire2).unwrap();
        wire2.truncate(n);
        let (len, _) = receiver.decrypt(session_id, &wire2, &mut out).unwrap();
        assert_eq!(&out[..len], plain_text);
        assert_eq!(receiver.packets_received(), 2);
    }

    #[test]
    fn has_valid_keys_requires_both_self_and_peer() {
        let mut session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        assert!(!session.has_valid_keys());

        session.update_next_self_key(ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE])).unwrap();
        session.promote_self_key();
        assert!(!session.has_valid_keys()); // peer key still missing

        session.update_peer_key(ExpresslaneKey([2u8; EXPRESSLANE_KEY_SIZE])).unwrap();
        assert!(session.has_valid_keys());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p lightway-expresslane session::`
Expected: FAIL to compile — `decrypt`, `update_peer_key`, `has_valid_keys`, `packets_received` are not defined.

- [ ] **Step 3: Implement the RX domain**

Add to the `impl ExpresslaneSession` block in `lightway-expresslane/src/session.rs`, after `encrypt`:

```rust
    // ---- RX domain: caller must externally serialize all calls in this
    // group against the same session handle. ----

    /// Install a new peer (receive) key. The previous peer key becomes the
    /// fallback used by `decrypt` for packets still in flight from before
    /// the peer's rotation.
    pub fn update_peer_key(&mut self, key: ExpresslaneKey) -> ExpresslaneResult<()> {
        let cipher = Cipher::new(&key)?;
        self.prev_peer = std::mem::replace(&mut self.current_peer, Some(cipher));
        Ok(())
    }

    /// True if both a self (send) key and a peer (receive) key are
    /// installed.
    pub fn has_valid_keys(&mut self) -> bool {
        self.current_peer.is_some()
            && self
                .current_self
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
    }

    /// Total number of packets successfully decrypted so far.
    pub fn packets_received(&mut self) -> u64 {
        self.replay_window.packets_received()
    }

    /// Decrypt `wire_packet` (ExpressLane wire format) into `out`. `out`
    /// must have capacity for at least `wire_packet.len() - WIRE_OVERHEAD`
    /// bytes. Returns `(plaintext_len, is_encoded)`.
    pub fn decrypt(
        &mut self,
        session_id: [u8; 8],
        wire_packet: &[u8],
        out: &mut [u8],
    ) -> ExpresslaneResult<(usize, bool)> {
        if wire_packet.len() < Self::WIRE_OVERHEAD {
            return Err(ExpresslaneError::InsufficientData);
        }

        let counter = u64::from_be_bytes(wire_packet[0..8].try_into().unwrap());

        if self.replay_window.would_reject(counter) {
            return Err(ExpresslaneError::Replayed);
        }

        let iv: [u8; 12] = wire_packet[8..20].try_into().unwrap();
        let tag: [u8; 16] = wire_packet[20..36].try_into().unwrap();
        let data_len = u16::from_be_bytes(wire_packet[36..38].try_into().unwrap()) as usize;
        let flags = u16::from_be_bytes(wire_packet[38..40].try_into().unwrap());
        let is_encoded = flags & 0x8000 != 0;

        if wire_packet.len() < Self::WIRE_OVERHEAD + data_len {
            return Err(ExpresslaneError::InsufficientData);
        }
        if out.len() < data_len {
            return Err(ExpresslaneError::BufferTooSmall);
        }

        let (aad_buf, aad_len) = build_aad(self.version, session_id, counter, is_encoded);
        out[..data_len].copy_from_slice(&wire_packet[40..40 + data_len]);

        let current = self.current_peer.as_ref().ok_or(ExpresslaneError::KeyNotSet)?;
        if current.decrypt(&iv, &aad_buf[..aad_len], &mut out[..data_len], &tag).is_err() {
            match self.prev_peer.as_ref() {
                Some(prev) => {
                    prev.decrypt(&iv, &aad_buf[..aad_len], &mut out[..data_len], &tag)?;
                }
                None => return Err(ExpresslaneError::InvalidData),
            }
        }

        if !self.replay_window.commit(counter) {
            return Err(ExpresslaneError::Replayed);
        }

        Ok((data_len, is_encoded))
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p lightway-expresslane session::`
Expected: 18 passed (8 from Task 7 + 10 new).

Run: `cargo test -p lightway-expresslane`
Expected: all tests across all modules pass (key, version, cipher, replay_window, session).

- [ ] **Step 5: Commit**

```bash
jj commit -m "expresslane: add ExpresslaneSession RX domain (decrypt) and round-trip tests"
```

---

## Task 9: Concurrency test

**Files:**
- Modify: `lightway-expresslane/src/session.rs`

**Interfaces:**
- Consumes: `ExpresslaneSession` (Tasks 7-8), unchanged.
- Produces: no new public API — proves the TX-domain concurrency contract documented in the spec.

- [ ] **Step 1: Write the tests**

Add to the `#[cfg(test)] mod tests` block in `lightway-expresslane/src/session.rs`:

```rust
    #[test]
    fn concurrent_encrypt_from_multiple_threads_produces_unique_counters_and_decrypts() {
        let key = ExpresslaneKey([7u8; EXPRESSLANE_KEY_SIZE]);
        let tx = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        tx.update_next_self_key(key).unwrap();
        tx.promote_self_key();

        let session_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        const THREADS: usize = 8;
        const PER_THREAD: usize = 50;

        let packets: Vec<Vec<u8>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|t| {
                    let tx = &tx;
                    scope.spawn(move || {
                        let mut produced = Vec::with_capacity(PER_THREAD);
                        for i in 0..PER_THREAD {
                            let counter = tx.reserve_counter();
                            let plain_text = format!("thread {t} packet {i}");
                            let mut buf =
                                vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
                            let iv = [t as u8; 12];
                            let n = tx
                                .encrypt(counter, session_id, plain_text.as_bytes(), iv, false, &mut buf)
                                .unwrap();
                            buf.truncate(n);
                            produced.push(buf);
                        }
                        produced
                    })
                })
                .collect();
            handles.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });

        assert_eq!(packets.len(), THREADS * PER_THREAD);

        let mut counters: Vec<u64> = packets
            .iter()
            .map(|p| u64::from_be_bytes(p[0..8].try_into().unwrap()))
            .collect();
        counters.sort_unstable();
        counters.dedup();
        assert_eq!(counters.len(), THREADS * PER_THREAD, "counters must all be unique");

        let mut rx = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        rx.update_peer_key(key).unwrap();
        for packet in &packets {
            let mut out = vec![0u8; packet.len() - ExpresslaneSession::WIRE_OVERHEAD];
            let (n, _) = rx.decrypt(session_id, packet, &mut out).unwrap();
            assert_eq!(n, out.len());
        }
        assert_eq!(rx.packets_received(), (THREADS * PER_THREAD) as u64);
    }

    #[test]
    fn promote_self_key_mid_stream_does_not_corrupt_in_flight_encrypt() {
        let key_a = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        let key_b = ExpresslaneKey([2u8; EXPRESSLANE_KEY_SIZE]);
        let tx = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        tx.update_next_self_key(key_a).unwrap();
        tx.promote_self_key();
        tx.update_next_self_key(key_b).unwrap();

        let session_id = [9u8; 8];
        let plain_text = b"rotate me";

        let packets = std::thread::scope(|scope| {
            let encryptor = {
                let tx = &tx;
                scope.spawn(move || {
                    let mut results = Vec::new();
                    for _ in 0..200 {
                        let counter = tx.reserve_counter();
                        let mut buf = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
                        if let Ok(n) =
                            tx.encrypt(counter, session_id, plain_text, [0u8; 12], false, &mut buf)
                        {
                            buf.truncate(n);
                            results.push(buf);
                        }
                    }
                    results
                })
            };
            std::thread::sleep(std::time::Duration::from_millis(1));
            tx.promote_self_key();
            encryptor.join().unwrap()
        });

        assert!(!packets.is_empty());

        // Every produced packet must decrypt with one of the two known
        // keys - none corrupted by the concurrent rotation.
        let mut rx = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        rx.update_peer_key(key_a).unwrap();
        rx.update_peer_key(key_b).unwrap(); // key_b current, key_a prev - both tried
        for packet in &packets {
            let mut out = vec![0u8; packet.len() - ExpresslaneSession::WIRE_OVERHEAD];
            rx.decrypt(session_id, packet, &mut out)
                .unwrap_or_else(|e| panic!("packet failed to decrypt: {e}"));
        }
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p lightway-expresslane session:: -- --test-threads=1`
Expected: these two tests should compile and pass immediately since they only use the public API already implemented in Tasks 7-8 — there's no new implementation step. If either test fails, it indicates a genuine concurrency bug in Task 7/8's implementation (most likely: a data race on `packets_sent`/`next_counter`, or a borrow-checker-legal-but-logically-wrong ordering in `encrypt`/`promote_self_key`) — fix `session.rs` before proceeding, don't weaken the test.

- [ ] **Step 3: Run the full test suite, including under a higher thread count for confidence**

Run: `for i in 1 2 3 4 5; do cargo test -p lightway-expresslane session::concurrent session::promote_self_key_mid_stream || break; done`
Expected: 5/5 runs pass (repeated runs catch flaky interleavings a single run might miss).

- [ ] **Step 4: Commit**

```bash
jj commit -m "expresslane: add concurrency tests for parallel encrypt"
```

---

## Task 10: Scaffold the `lightway-expresslane-cffi` crate — types, opaque handle, create/destroy

**Files:**
- Modify: `Cargo.toml` (repo root — add `lightway-expresslane-cffi` to `members`; see Step 0)
- Create: `lightway-expresslane-cffi/Cargo.toml`
- Create: `lightway-expresslane-cffi/build.rs`
- Create: `lightway-expresslane-cffi/cbindgen.toml`
- Create: `lightway-expresslane-cffi/src/types.rs`
- Create: `lightway-expresslane-cffi/src/lib.rs`

**Interfaces:**
- Consumes: `lightway_expresslane::{ExpresslaneSession, ExpresslaneVersion, ExpresslaneError}` (Tasks 4, 5, 7, 8).
- Produces: `he_expresslane_return_code_t`, `he_expresslane_version_t` (C enums), `he_expresslane_session_t` (opaque handle), `he_expresslane_session_create`, `he_expresslane_session_destroy`, and the `ffi_guard` helper reused by all later C-API tasks.

- [ ] **Step 0: Add `lightway-expresslane-cffi` to the root workspace `members`**

Per Task 1's corrected sequencing, the root `Cargo.toml`'s `[workspace]` table currently reads:

```toml
[workspace]
members = ["lightway-expresslane"]
```

Change it to:

```toml
[workspace]
members = ["lightway-expresslane", "lightway-expresslane-cffi"]
```

This can only land together with (or after) Step 1 below creating `lightway-expresslane-cffi/Cargo.toml` — adding the member first, alone, would reproduce the same "failed to load manifest" failure Task 1/3 hit and break `cargo test -p lightway-expresslane` for the rest of this task's own verification steps. Make this edit as part of the same commit as Step 1-5 below, not as a separate earlier step.

- [ ] **Step 1: Create `lightway-expresslane-cffi/Cargo.toml`**

```toml
[package]
name = "lightway-expresslane-cffi"
version = "0.1.0"
edition = "2024"
description = "C ABI for ExpressLane data-packet encrypt/decrypt primitives (lightway-expresslane)."
license = "AGPL-3.0-only"
repository = "https://github.com/expressvpn/lightway-cffi"

[lib]
crate-type = ["cdylib", "staticlib", "rlib"]

[lints.rust]
unsafe_op_in_unsafe_fn = "deny"
[lints.clippy]
undocumented_unsafe_blocks = "deny"

[dependencies]
lightway-expresslane = { path = "../lightway-expresslane" }

[build-dependencies]
cbindgen = "0.29"
```

- [ ] **Step 2: Create `lightway-expresslane-cffi/build.rs`**

```rust
//! Build script: regenerate `include/lightway_expresslane_cffi.h` from the
//! crate's `extern "C"` surface using cbindgen.
//!
//! The header is committed to the repo (under `include/`) so consumers can
//! rely on it without running `cargo build` first; this build script keeps
//! it in sync with the Rust sources during development.

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("cbindgen.toml");
    let out_header = crate_dir.join("include").join("lightway_expresslane_cffi.h");

    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");

    if env::var_os("LIGHTWAY_CFFI_SKIP_CBINDGEN").is_some() {
        return;
    }

    let config = cbindgen::Config::from_file(&config_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", config_path.display()));

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            if let Some(parent) = out_header.parent() {
                std::fs::create_dir_all(parent).expect("create include dir");
            }
            bindings.write_to_file(&out_header);
        }
        Err(e) => {
            println!("cargo:warning=cbindgen failed to regenerate header: {e}");
        }
    }
}
```

- [ ] **Step 3: Create `lightway-expresslane-cffi/cbindgen.toml`**

```toml
# cbindgen configuration for lightway-expresslane-cffi.

language = "C"
pragma_once = true
include_guard = "XV_LIGHTWAY_EXPRESSLANE_CFFI_H"
tab_width = 4
documentation = true
documentation_style = "c"
style = "type"
cpp_compat = true
no_includes = false
sys_includes = ["stdint.h", "stddef.h", "stdbool.h"]

header = """
/*
 * lightway-expresslane-cffi: C ABI for ExpressLane data-packet
 * encrypt/decrypt primitives (lightway-expresslane, pure Rust).
 *
 * This header is auto-generated by cbindgen. DO NOT EDIT BY HAND.
 */
"""

[export]
prefix = ""
include = [
    # he_expresslane_session_create takes a raw uint8_t (not this enum) so
    # an out-of-range value from C can be rejected safely instead of
    # reinterpreted as an invalid discriminant. Force emission so the
    # HE_EXPRESSLANE_VERSION_* constants stay available to callers.
    "he_expresslane_version_t",
]

[enum]
prefix_with_name = false
rename_variants = "ScreamingSnakeCase"

[parse]
parse_deps = false
```

- [ ] **Step 4: Create `lightway-expresslane-cffi/src/types.rs`**

```rust
//! C-ABI types for the ExpressLane data-plane CFFI.
#![allow(non_camel_case_types, non_upper_case_globals, clippy::upper_case_acronyms)]

/// Return codes used by all `he_expresslane_*` functions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_expresslane_return_code_t {
    /// Operation succeeded.
    HE_EXPRESSLANE_SUCCESS = 0,
    /// A null pointer was supplied where one is not permitted.
    HE_EXPRESSLANE_ERR_NULL_POINTER = -1,
    /// Caller-provided output buffer is too small.
    HE_EXPRESSLANE_ERR_BUFFER_TOO_SMALL = -2,
    /// Wire packet is shorter than the minimum ExpressLane header.
    HE_EXPRESSLANE_ERR_INSUFFICIENT_DATA = -3,
    /// AEAD authentication failed, or the packet is otherwise malformed.
    HE_EXPRESSLANE_ERR_INVALID_DATA = -4,
    /// Wire counter was rejected by the replay window.
    HE_EXPRESSLANE_ERR_REPLAYED = -5,
    /// No key is installed for this operation.
    HE_EXPRESSLANE_ERR_KEY_NOT_SET = -6,
    /// Key material could not be loaded into the cipher.
    HE_EXPRESSLANE_ERR_INVALID_KEY = -7,
    /// A panic was caught at the FFI boundary.
    HE_EXPRESSLANE_ERR_PANIC = -8,
}

impl From<lightway_expresslane::ExpresslaneError> for he_expresslane_return_code_t {
    fn from(e: lightway_expresslane::ExpresslaneError) -> Self {
        use lightway_expresslane::ExpresslaneError as E;
        match e {
            E::InsufficientData => Self::HE_EXPRESSLANE_ERR_INSUFFICIENT_DATA,
            E::BufferTooSmall => Self::HE_EXPRESSLANE_ERR_BUFFER_TOO_SMALL,
            E::InvalidData => Self::HE_EXPRESSLANE_ERR_INVALID_DATA,
            E::Replayed => Self::HE_EXPRESSLANE_ERR_REPLAYED,
            E::KeyNotSet => Self::HE_EXPRESSLANE_ERR_KEY_NOT_SET,
            E::InvalidKey => Self::HE_EXPRESSLANE_ERR_INVALID_KEY,
        }
    }
}

/// ExpressLane wire-format version, matching `lightway_expresslane::ExpresslaneVersion`.
///
/// `he_expresslane_session_create` takes a raw `uint8_t` rather than this
/// enum type directly, so these constants are provided for callers to use
/// by name; cbindgen forces their emission via `cbindgen.toml`'s
/// `[export] include`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_expresslane_version_t {
    /// Not yet negotiated / not recognised by this build.
    HE_EXPRESSLANE_VERSION_UNKNOWN = 0,
    /// Initial ExpressLane wire format.
    HE_EXPRESSLANE_VERSION_1 = 1,
    /// Flags byte bound into the AEAD AAD.
    HE_EXPRESSLANE_VERSION_2 = 2,
}
```

- [ ] **Step 5: Create `lightway-expresslane-cffi/src/lib.rs`**

```rust
//! lightway-expresslane-cffi: C ABI for `lightway-expresslane`.
//!
//! Exposes ExpressLane data-packet encrypt/decrypt as a standalone C API,
//! independent of the full `lightway-cffi` client (`he_conn_t`), for
//! out-of-process packet crypto (e.g. a Windows driver-adjacent process).
//! Deliberately has no wolfssl/TLS dependency.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![allow(non_camel_case_types, non_upper_case_globals, clippy::upper_case_acronyms)]

use std::panic::{AssertUnwindSafe, catch_unwind};

pub mod types;

use lightway_expresslane::{ExpresslaneSession, ExpresslaneVersion};
use types::he_expresslane_version_t;

pub use types::he_expresslane_return_code_t;

/// Run an FFI entry-point body, converting any panic into `default` instead
/// of letting it unwind across the C ABI boundary (which aborts the
/// process).
#[inline]
fn ffi_guard<R>(default: R, f: impl FnOnce() -> R) -> R {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(default)
}

/// Opaque ExpressLane packet-crypto session handle.
pub struct he_expresslane_session_t(ExpresslaneSession);

/// Allocate a new ExpressLane session for the given wire version.
///
/// `version` is a raw byte (0 = unknown, 1 = V1, 2 = V2 — see
/// `he_expresslane_version_t`) rather than the enum type directly, so an
/// out-of-range value from C falls back to `HE_EXPRESSLANE_VERSION_UNKNOWN`
/// instead of being reinterpreted as an invalid discriminant.
///
/// Returns a heap-allocated pointer. The caller must free it with
/// `he_expresslane_session_destroy`.
///
/// # Safety
/// The returned pointer must be freed with `he_expresslane_session_destroy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_session_create(
    version: u8,
) -> *mut he_expresslane_session_t {
    let version = ExpresslaneVersion::from(version);
    Box::into_raw(Box::new(he_expresslane_session_t(ExpresslaneSession::new(
        version,
    ))))
}

/// Free a session previously allocated by `he_expresslane_session_create`.
///
/// # Safety
/// `session` must be a valid pointer obtained from
/// `he_expresslane_session_create` and must not be used after this call.
/// The caller must ensure no other thread is calling any
/// `he_expresslane_*` function on this handle concurrently with (or after)
/// destruction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_session_destroy(session: *mut he_expresslane_session_t) {
    if !session.is_null() {
        // SAFETY: pointer was created by Box::into_raw in
        // he_expresslane_session_create.
        unsafe { drop(Box::from_raw(session)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_destroy() {
        let session = unsafe { he_expresslane_session_create(2) };
        assert!(!session.is_null());
        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn destroy_null_is_a_no_op() {
        unsafe { he_expresslane_session_destroy(std::ptr::null_mut()) };
    }

    #[test]
    fn create_with_unknown_version_byte_falls_back_safely() {
        let session = unsafe { he_expresslane_session_create(255) };
        assert!(!session.is_null());
        unsafe { he_expresslane_session_destroy(session) };
    }
}
```

- [ ] **Step 6: Verify the crate builds and its tests pass**

Run: `cargo test -p lightway-expresslane-cffi`
Expected: 3 passed.

Run: `cargo build`
Expected: builds all three crates (`lightway-cffi`, `lightway-expresslane`, `lightway-expresslane-cffi`) successfully, and generates `lightway-expresslane-cffi/include/lightway_expresslane_cffi.h`.

Run: `cat lightway-expresslane-cffi/include/lightway_expresslane_cffi.h`
Expected: a generated header declaring `he_expresslane_return_code_t`, `he_expresslane_version_t`, `he_expresslane_session_t`, `he_expresslane_session_create`, `he_expresslane_session_destroy`.

- [ ] **Step 7: Commit**

```bash
jj commit -m "expresslane-cffi: scaffold crate, types, session create/destroy"
```

---

## Task 11: C API — TX domain (`reserve_counter`, key rotation, `packets_sent`, `encrypt`)

**Files:**
- Modify: `lightway-expresslane-cffi/src/lib.rs`

**Interfaces:**
- Consumes: `he_expresslane_session_t`, `ffi_guard`, `he_expresslane_return_code_t` (Task 10); `lightway_expresslane::{ExpresslaneKey, EXPRESSLANE_KEY_SIZE}`.
- Produces: `he_expresslane_reserve_counter`, `he_expresslane_set_next_self_key`, `he_expresslane_promote_self_key`, `he_expresslane_packets_sent`, `he_expresslane_encrypt`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `lightway-expresslane-cffi/src/lib.rs`:

```rust
    #[test]
    fn reserve_counter_increments() {
        let session = unsafe { he_expresslane_session_create(2) };
        assert_eq!(unsafe { he_expresslane_reserve_counter(session) }, 1);
        assert_eq!(unsafe { he_expresslane_reserve_counter(session) }, 2);
        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn reserve_counter_null_session_returns_zero() {
        assert_eq!(unsafe { he_expresslane_reserve_counter(std::ptr::null()) }, 0);
    }

    #[test]
    fn set_next_self_key_null_pointers_return_null_pointer_error() {
        let session = unsafe { he_expresslane_session_create(2) };
        let key = [1u8; 32];
        assert_eq!(
            unsafe { he_expresslane_set_next_self_key(std::ptr::null(), key.as_ptr()) },
            he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER
        );
        assert_eq!(
            unsafe { he_expresslane_set_next_self_key(session, std::ptr::null()) },
            he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER
        );
        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn set_and_promote_key_then_encrypt_succeeds() {
        let session = unsafe { he_expresslane_session_create(2) };
        let key = [1u8; 32];
        assert_eq!(
            unsafe { he_expresslane_set_next_self_key(session, key.as_ptr()) },
            he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS
        );
        unsafe { he_expresslane_promote_self_key(session) };

        let session_id = [1u8; 8];
        let plain_text = b"test data";
        let iv = [0u8; 12];
        let mut out = vec![0u8; lightway_expresslane::ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let mut out_len: usize = 0;

        let counter = unsafe { he_expresslane_reserve_counter(session) };
        let rc = unsafe {
            he_expresslane_encrypt(
                session,
                counter,
                session_id.as_ptr(),
                plain_text.as_ptr(),
                plain_text.len(),
                iv.as_ptr(),
                false,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS);
        assert_eq!(out_len, out.len());

        assert_eq!(unsafe { he_expresslane_packets_sent(session) }, 1);
        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn encrypt_without_key_returns_key_not_set() {
        let session = unsafe { he_expresslane_session_create(2) };
        let session_id = [1u8; 8];
        let plain_text = b"test";
        let iv = [0u8; 12];
        let mut out = vec![0u8; lightway_expresslane::ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let mut out_len: usize = 0;

        let rc = unsafe {
            he_expresslane_encrypt(
                session,
                1,
                session_id.as_ptr(),
                plain_text.as_ptr(),
                plain_text.len(),
                iv.as_ptr(),
                false,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_KEY_NOT_SET);
        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn encrypt_buffer_too_small_returns_error() {
        let session = unsafe { he_expresslane_session_create(2) };
        let key = [1u8; 32];
        unsafe { he_expresslane_set_next_self_key(session, key.as_ptr()) };
        unsafe { he_expresslane_promote_self_key(session) };

        let session_id = [1u8; 8];
        let plain_text = b"test";
        let iv = [0u8; 12];
        let mut out = vec![0u8; 4]; // too small
        let mut out_len: usize = 0;

        let rc = unsafe {
            he_expresslane_encrypt(
                session,
                1,
                session_id.as_ptr(),
                plain_text.as_ptr(),
                plain_text.len(),
                iv.as_ptr(),
                false,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_BUFFER_TOO_SMALL);
        unsafe { he_expresslane_session_destroy(session) };
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p lightway-expresslane-cffi`
Expected: FAIL to compile — `he_expresslane_reserve_counter`, `he_expresslane_set_next_self_key`, `he_expresslane_promote_self_key`, `he_expresslane_packets_sent`, `he_expresslane_encrypt` are not defined.

- [ ] **Step 3: Implement the TX-domain C functions**

Add to `lightway-expresslane-cffi/src/lib.rs`, after `he_expresslane_session_destroy` and before `#[cfg(test)]`:

```rust
use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};

/// Reserve a wire counter value guaranteed unique for this session. Safe to
/// call concurrently from multiple threads on the same session. Returns 0
/// if `session` is null (0 is never a value `reserve_counter` itself would
/// return, since it starts at 1).
///
/// # Safety
/// `session` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_reserve_counter(
    session: *const he_expresslane_session_t,
) -> u64 {
    if session.is_null() {
        return 0;
    }
    // SAFETY: null check above; session is valid for this call.
    unsafe { &*session }.0.reserve_counter()
}

/// Stage a new "next self" key. Call `he_expresslane_promote_self_key` once
/// the peer has acknowledged the rotation to make it the active send key.
/// Safe to call concurrently with `he_expresslane_encrypt` on the same
/// session.
///
/// # Safety
/// `session` must be a valid non-null pointer. `key` must point to 32
/// readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_set_next_self_key(
    session: *const he_expresslane_session_t,
    key: *const u8,
) -> he_expresslane_return_code_t {
    if session.is_null() || key.is_null() {
        return he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER;
    }
    ffi_guard(he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_PANIC, || {
        // SAFETY: null checks above; key points to EXPRESSLANE_KEY_SIZE
        // readable bytes per the function's documented contract.
        let key_bytes: [u8; EXPRESSLANE_KEY_SIZE] =
            unsafe { std::slice::from_raw_parts(key, EXPRESSLANE_KEY_SIZE) }
                .try_into()
                .expect("slice has exactly EXPRESSLANE_KEY_SIZE bytes");
        // SAFETY: null check above; session is valid for this call.
        match unsafe { &*session }
            .0
            .update_next_self_key(ExpresslaneKey::from(key_bytes))
        {
            Ok(()) => he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS,
            Err(e) => e.into(),
        }
    })
}

/// Promote the staged "next self" key to the active send key. A no-op if
/// no key is staged. Safe to call concurrently with `he_expresslane_encrypt`
/// on the same session.
///
/// # Safety
/// `session` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_promote_self_key(
    session: *const he_expresslane_session_t,
) {
    if session.is_null() {
        return;
    }
    // SAFETY: null check above; session is valid for this call.
    unsafe { &*session }.0.promote_self_key();
}

/// Total number of packets successfully encrypted so far on this session.
///
/// # Safety
/// `session` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_packets_sent(
    session: *const he_expresslane_session_t,
) -> u64 {
    if session.is_null() {
        return 0;
    }
    // SAFETY: null check above; session is valid for this call.
    unsafe { &*session }.0.packets_sent()
}

/// Encrypt `plain_text` into ExpressLane wire format. Safe to call
/// concurrently from multiple threads on the same session, provided each
/// call uses a unique `counter` (see `he_expresslane_reserve_counter`).
///
/// `out` must have capacity for at least
/// `he_expresslane_wire_overhead() + plain_text_len` bytes. On success,
/// `*out_len` is set to the number of bytes written to `out`.
///
/// # Safety
/// `session` must be a valid non-null pointer. `session_id` must point to 8
/// readable bytes. `plain_text` must point to `plain_text_len` readable
/// bytes. `iv` must point to 12 readable bytes. `out` must point to
/// `out_capacity` writable bytes. `out_len` must be a valid pointer to a
/// `size_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_encrypt(
    session: *const he_expresslane_session_t,
    counter: u64,
    session_id: *const u8,
    plain_text: *const u8,
    plain_text_len: usize,
    iv: *const u8,
    is_encoded: bool,
    out: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> he_expresslane_return_code_t {
    if session.is_null()
        || session_id.is_null()
        || plain_text.is_null()
        || iv.is_null()
        || out.is_null()
        || out_len.is_null()
    {
        return he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER;
    }
    ffi_guard(he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_PANIC, || {
        // SAFETY: null checks above; each pointer is valid for the length
        // documented in this function's `# Safety` section.
        let session_id_bytes: [u8; 8] =
            unsafe { std::slice::from_raw_parts(session_id, 8) }.try_into().unwrap();
        let plain_text_slice = unsafe { std::slice::from_raw_parts(plain_text, plain_text_len) };
        let iv_bytes: [u8; 12] = unsafe { std::slice::from_raw_parts(iv, 12) }.try_into().unwrap();
        let out_slice = unsafe { std::slice::from_raw_parts_mut(out, out_capacity) };

        // SAFETY: null check above; session is valid for this call.
        let result = unsafe { &*session }.0.encrypt(
            counter,
            session_id_bytes,
            plain_text_slice,
            iv_bytes,
            is_encoded,
            out_slice,
        );
        match result {
            Ok(written) => {
                // SAFETY: null check above; out_len is a valid pointer to a
                // writable size_t per the function's documented contract.
                unsafe { *out_len = written };
                he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS
            }
            Err(e) => e.into(),
        }
    })
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p lightway-expresslane-cffi`
Expected: all tests pass (3 from Task 10 + 6 new = 9).

- [ ] **Step 5: Commit**

```bash
jj commit -m "expresslane-cffi: add TX-domain C API (reserve_counter, key rotation, encrypt)"
```

---

## Task 12: C API — RX domain (`set_peer_key`, `has_valid_keys`, `packets_received`, `decrypt`, `wire_overhead`)

**Files:**
- Modify: `lightway-expresslane-cffi/src/lib.rs`

**Interfaces:**
- Consumes: same as Task 11.
- Produces: `he_expresslane_set_peer_key`, `he_expresslane_has_valid_keys`, `he_expresslane_packets_received`, `he_expresslane_decrypt`, `he_expresslane_wire_overhead`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `lightway-expresslane-cffi/src/lib.rs`:

```rust
    #[test]
    fn wire_overhead_is_40() {
        assert_eq!(he_expresslane_wire_overhead(), 40);
    }

    #[test]
    fn has_valid_keys_false_until_both_keys_set() {
        let session = unsafe { he_expresslane_session_create(2) };
        assert!(!unsafe { he_expresslane_has_valid_keys(session) });

        let key = [1u8; 32];
        unsafe { he_expresslane_set_next_self_key(session, key.as_ptr()) };
        unsafe { he_expresslane_promote_self_key(session) };
        assert!(!unsafe { he_expresslane_has_valid_keys(session) }); // peer still missing

        assert_eq!(
            unsafe { he_expresslane_set_peer_key(session, key.as_ptr()) },
            he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS
        );
        assert!(unsafe { he_expresslane_has_valid_keys(session) });

        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn encrypt_then_decrypt_round_trips_through_the_c_api() {
        let sender = unsafe { he_expresslane_session_create(2) };
        let receiver = unsafe { he_expresslane_session_create(2) };
        let key = [42u8; 32];

        unsafe { he_expresslane_set_next_self_key(sender, key.as_ptr()) };
        unsafe { he_expresslane_promote_self_key(sender) };
        unsafe { he_expresslane_set_peer_key(receiver, key.as_ptr()) };

        let session_id = [1u8; 8];
        let plain_text = b"Hello, ExpressLane!";
        let iv = [9u8; 12];
        let overhead = he_expresslane_wire_overhead();

        let mut wire = vec![0u8; overhead + plain_text.len()];
        let mut wire_len: usize = 0;
        let counter = unsafe { he_expresslane_reserve_counter(sender) };
        let rc = unsafe {
            he_expresslane_encrypt(
                sender,
                counter,
                session_id.as_ptr(),
                plain_text.as_ptr(),
                plain_text.len(),
                iv.as_ptr(),
                false,
                wire.as_mut_ptr(),
                wire.len(),
                &mut wire_len,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS);

        let mut out = vec![0u8; plain_text.len()];
        let mut out_len: usize = 0;
        let mut is_encoded = true; // must be overwritten to false
        let rc = unsafe {
            he_expresslane_decrypt(
                receiver,
                session_id.as_ptr(),
                wire.as_ptr(),
                wire_len,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
                &mut is_encoded,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS);
        assert_eq!(out_len, plain_text.len());
        assert!(!is_encoded);
        assert_eq!(&out[..out_len], plain_text);
        assert_eq!(unsafe { he_expresslane_packets_received(receiver) }, 1);

        unsafe { he_expresslane_session_destroy(sender) };
        unsafe { he_expresslane_session_destroy(receiver) };
    }

    #[test]
    fn decrypt_without_key_returns_key_not_set() {
        let receiver = unsafe { he_expresslane_session_create(2) };
        let session_id = [1u8; 8];
        let wire = vec![0u8; he_expresslane_wire_overhead()];
        let mut out = vec![0u8; 4];
        let mut out_len: usize = 0;
        let mut is_encoded = false;

        let rc = unsafe {
            he_expresslane_decrypt(
                receiver,
                session_id.as_ptr(),
                wire.as_ptr(),
                wire.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
                &mut is_encoded,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_KEY_NOT_SET);
        unsafe { he_expresslane_session_destroy(receiver) };
    }

    #[test]
    fn decrypt_null_pointers_return_null_pointer_error() {
        let receiver = unsafe { he_expresslane_session_create(2) };
        let session_id = [1u8; 8];
        let wire = vec![0u8; he_expresslane_wire_overhead()];
        let mut out = vec![0u8; 4];
        let mut out_len: usize = 0;
        let mut is_encoded = false;

        let rc = unsafe {
            he_expresslane_decrypt(
                std::ptr::null_mut(),
                session_id.as_ptr(),
                wire.as_ptr(),
                wire.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
                &mut is_encoded,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER);
        unsafe { he_expresslane_session_destroy(receiver) };
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p lightway-expresslane-cffi`
Expected: FAIL to compile — `he_expresslane_wire_overhead`, `he_expresslane_set_peer_key`, `he_expresslane_has_valid_keys`, `he_expresslane_packets_received`, `he_expresslane_decrypt` are not defined.

- [ ] **Step 3: Implement the RX-domain C functions**

Add to `lightway-expresslane-cffi/src/lib.rs`, after `he_expresslane_encrypt` and before `#[cfg(test)]`:

```rust
/// Install a new peer (receive) key. The previous peer key becomes the
/// fallback used by `he_expresslane_decrypt` for packets still in flight
/// from before the peer's rotation. Caller must externally serialize this
/// call against `he_expresslane_decrypt`/`he_expresslane_has_valid_keys`/
/// `he_expresslane_packets_received` on the same session.
///
/// # Safety
/// `session` must be a valid non-null pointer. `key` must point to 32
/// readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_set_peer_key(
    session: *mut he_expresslane_session_t,
    key: *const u8,
) -> he_expresslane_return_code_t {
    if session.is_null() || key.is_null() {
        return he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER;
    }
    ffi_guard(he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_PANIC, || {
        // SAFETY: null checks above; key points to EXPRESSLANE_KEY_SIZE
        // readable bytes per the function's documented contract.
        let key_bytes: [u8; EXPRESSLANE_KEY_SIZE] =
            unsafe { std::slice::from_raw_parts(key, EXPRESSLANE_KEY_SIZE) }
                .try_into()
                .expect("slice has exactly EXPRESSLANE_KEY_SIZE bytes");
        // SAFETY: null check above; session is valid for this call.
        match unsafe { &mut *session }
            .0
            .update_peer_key(ExpresslaneKey::from(key_bytes))
        {
            Ok(()) => he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS,
            Err(e) => e.into(),
        }
    })
}

/// True if both a self (send) key and a peer (receive) key are installed.
/// Caller must externally serialize this call against
/// `he_expresslane_decrypt`/`he_expresslane_set_peer_key` on the same
/// session.
///
/// # Safety
/// `session` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_has_valid_keys(
    session: *mut he_expresslane_session_t,
) -> bool {
    if session.is_null() {
        return false;
    }
    // SAFETY: null check above; session is valid for this call.
    unsafe { &mut *session }.0.has_valid_keys()
}

/// Total number of packets successfully decrypted so far on this session.
/// Caller must externally serialize this call against
/// `he_expresslane_decrypt` on the same session.
///
/// # Safety
/// `session` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_packets_received(
    session: *mut he_expresslane_session_t,
) -> u64 {
    if session.is_null() {
        return 0;
    }
    // SAFETY: null check above; session is valid for this call.
    unsafe { &mut *session }.0.packets_received()
}

/// Decrypt `wire_packet` (ExpressLane wire format) into `out`. `out` must
/// have capacity for at least `wire_packet_len - he_expresslane_wire_overhead()`
/// bytes. On success, `*out_len` is set to the plaintext length and
/// `*is_encoded` to the packet's encoded flag. Caller must externally
/// serialize this call against `he_expresslane_set_peer_key`/
/// `he_expresslane_has_valid_keys`/`he_expresslane_packets_received` on the
/// same session — no internal locking.
///
/// # Safety
/// `session` must be a valid non-null pointer. `session_id` must point to 8
/// readable bytes. `wire_packet` must point to `wire_packet_len` readable
/// bytes. `out` must point to `out_capacity` writable bytes. `out_len` and
/// `is_encoded` must be valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_decrypt(
    session: *mut he_expresslane_session_t,
    session_id: *const u8,
    wire_packet: *const u8,
    wire_packet_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
    is_encoded: *mut bool,
) -> he_expresslane_return_code_t {
    if session.is_null()
        || session_id.is_null()
        || wire_packet.is_null()
        || out.is_null()
        || out_len.is_null()
        || is_encoded.is_null()
    {
        return he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER;
    }
    ffi_guard(he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_PANIC, || {
        // SAFETY: null checks above; each pointer is valid for the length
        // documented in this function's `# Safety` section.
        let session_id_bytes: [u8; 8] =
            unsafe { std::slice::from_raw_parts(session_id, 8) }.try_into().unwrap();
        let wire_slice = unsafe { std::slice::from_raw_parts(wire_packet, wire_packet_len) };
        let out_slice = unsafe { std::slice::from_raw_parts_mut(out, out_capacity) };

        // SAFETY: null check above; session is valid for this call.
        let result = unsafe { &mut *session }.0.decrypt(session_id_bytes, wire_slice, out_slice);
        match result {
            Ok((len, encoded)) => {
                // SAFETY: null checks above; out_len/is_encoded are valid
                // writable pointers per the function's documented contract.
                unsafe {
                    *out_len = len;
                    *is_encoded = encoded;
                }
                he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS
            }
            Err(e) => e.into(),
        }
    })
}

/// Wire overhead in bytes (40): counter(8) + iv(12) + tag(16) + data_len(2)
/// + flags(2). Use this to size buffers for `he_expresslane_encrypt` /
/// `he_expresslane_decrypt` without hardcoding the constant.
#[unsafe(no_mangle)]
pub extern "C" fn he_expresslane_wire_overhead() -> usize {
    ExpresslaneSession::WIRE_OVERHEAD
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p lightway-expresslane-cffi`
Expected: all tests pass (9 from Task 11 + 5 new = 14).

Run: `cargo test`
Expected: all tests across the whole workspace pass (`lightway-cffi`, `lightway-expresslane`, `lightway-expresslane-cffi`).

- [ ] **Step 5: Commit**

```bash
jj commit -m "expresslane-cffi: add RX-domain C API (peer key, decrypt, wire_overhead)"
```

---

## Task 13: CI wiring, header compile-check, README

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `lightway-expresslane-cffi/README.md`
- Modify: `README.md` (repo root)

**Interfaces:**
- Consumes: `lightway-expresslane-cffi/include/lightway_expresslane_cffi.h` (generated by Task 10's `build.rs`, committed to the repo).
- Produces: CI coverage for the new crates' header staying in sync and compiling as C/C++, matching the existing `lightway-cffi` crate's CI treatment exactly.

- [ ] **Step 1: Extend the `check-header` job to also verify the new header**

In `.github/workflows/ci.yml`, the existing `check-header` job's last step is:

```yaml
      - name: Verify header is unchanged
        run: |
          git diff --exit-code include/lightway_cffi.h || \
            (echo "::error::include/lightway_cffi.h is out of date. Run 'cargo build' and commit the result." && exit 1)
```

Replace it with:

```yaml
      - name: Verify headers are unchanged
        run: |
          git diff --exit-code include/lightway_cffi.h lightway-expresslane-cffi/include/lightway_expresslane_cffi.h || \
            (echo "::error::a generated header is out of date. Run 'cargo build' and commit the result." && exit 1)
```

(The job's earlier `Build (regenerates include/lightway_cffi.h)` step already runs `cargo build` at the workspace root, which now also regenerates `lightway-expresslane-cffi`'s header — no change needed there.)

- [ ] **Step 2: Extend the `header-compiles` job to also compile the new header**

The existing job is:

```yaml
  header-compiles:
    name: Header compiles as C/C++
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v5

      # Compile the committed header on its own (no Rust toolchain needed) so a
      # change that leaves it referencing an undefined type, etc., fails CI
      # instead of only being caught in review.
      - name: Compile committed header as C and C++
        run: |
          cat > /tmp/htest.c <<'EOF'
          #define XV_LIGHTWAY_CFFI_NO_PACKET_FILTER_INCLUDE
          #include "lightway_cffi.h"
          int main(void) { return 0; }
          EOF
          cp /tmp/htest.c /tmp/htest.cpp
          cc  -I include -Wall -Wextra -fsyntax-only /tmp/htest.c
          c++ -I include -Wall -Wextra -fsyntax-only /tmp/htest.cpp
```

Add a second step after it (same job, new header, no packet-filter include needed since `lightway_expresslane_cffi.h` doesn't reference that type):

```yaml
      - name: Compile committed ExpressLane header as C and C++
        run: |
          cat > /tmp/htest_expresslane.c <<'EOF'
          #include "lightway_expresslane_cffi.h"
          int main(void) { return 0; }
          EOF
          cp /tmp/htest_expresslane.c /tmp/htest_expresslane.cpp
          cc  -I lightway-expresslane-cffi/include -Wall -Wextra -fsyntax-only /tmp/htest_expresslane.c
          c++ -I lightway-expresslane-cffi/include -Wall -Wextra -fsyntax-only /tmp/htest_expresslane.cpp
```

- [ ] **Step 3: Create `lightway-expresslane-cffi/README.md`**

```markdown
# lightway-expresslane-cffi

C ABI for ExpressLane data-packet encrypt/decrypt, independent of the full
`lightway-cffi` client (`he_conn_t`).

## Purpose

Lets out-of-process code — a Windows usermode service today, potentially a
kernel-mode driver later — encrypt/decrypt individual ExpressLane data
packets directly, without linking the full `Connection` / TLS / IO-loop
machinery from `lightway-core`. Deliberately has no wolfssl/TLS dependency:
it links only `lightway-expresslane`, a pure-Rust reimplementation of the
ExpressLane data-packet wire protocol using the `aes-gcm` crate.

Key exchange and rotation timing stay in the full `lightway-cffi` client
(`he_expresslane_cb_t` / `he_expresslane_state_change_cb_t`). This crate is
scoped to the data-plane packet crypto only — see this repo's
`docs/superpowers/specs/2026-07-16-expresslane-data-cffi-design.md` for the
full design.

## API

- `he_expresslane_session_create` / `he_expresslane_session_destroy` — opaque
  session lifecycle.
- **TX domain** (safe to call concurrently from multiple threads on one
  session): `he_expresslane_reserve_counter`, `he_expresslane_set_next_self_key`,
  `he_expresslane_promote_self_key`, `he_expresslane_packets_sent`,
  `he_expresslane_encrypt`.
- **RX domain** (caller must externally serialize calls in this group on one
  session): `he_expresslane_set_peer_key`, `he_expresslane_has_valid_keys`,
  `he_expresslane_packets_received`, `he_expresslane_decrypt`.
- `he_expresslane_wire_overhead` — buffer sizing helper (40 bytes).

All buffers are caller-owned: `he_expresslane_encrypt`/`he_expresslane_decrypt`
write into a caller-provided output buffer and report bytes written; no
`Vec`/`Box` crosses the FFI boundary, and there is no matching `_free()`
function for packet buffers.

## Build

```
cargo build --release
```

Produces `liblightway_expresslane_cffi.{so,dylib}` / `lightway_expresslane_cffi.dll`
(cdylib) and `liblightway_expresslane_cffi.a` / `lightway_expresslane_cffi.lib`
(staticlib), plus `include/lightway_expresslane_cffi.h`.

Set `LIGHTWAY_CFFI_SKIP_CBINDGEN=1` to skip header regeneration during the
build (e.g. read-only source trees).
```

- [ ] **Step 4: Add a pointer to the new crate in the repo root README**

In the repo root `README.md`, the file opens with:

```markdown
# lightway-cffi

A C ABI shim over the Rust [`lightway-core`](https://github.com/expressvpn/lightway) crate,
exposing a `he_*` / `HE_*` API that is source-compatible with the OSS
`expressvpn/lightway-core` C library.

Consumers such as `kp_pkf_client` can link against `lightway_cffi.dll` /
`lightway_cffi.lib` and include `include/lightway_cffi.h` without any source
changes to their existing `lightway_tunnel.h` call sites.

## Features
```

Insert a new section between the two-paragraph intro and `## Features`:

```markdown
# lightway-cffi

A C ABI shim over the Rust [`lightway-core`](https://github.com/expressvpn/lightway) crate,
exposing a `he_*` / `HE_*` API that is source-compatible with the OSS
`expressvpn/lightway-core` C library.

Consumers such as `kp_pkf_client` can link against `lightway_cffi.dll` /
`lightway_cffi.lib` and include `include/lightway_cffi.h` without any source
changes to their existing `lightway_tunnel.h` call sites.

## Related crate: lightway-expresslane-cffi

This repo also contains
[`lightway-expresslane-cffi`](lightway-expresslane-cffi/README.md), a second,
independent C ABI for out-of-process ExpressLane data-packet encrypt/decrypt
— e.g. for a Windows driver-adjacent process that needs packet crypto without
linking this crate's full TLS/wolfssl-dependent client. It links only
`lightway-expresslane`, a pure-Rust reimplementation of the ExpressLane
data-packet wire protocol, and ships as its own `lightway_expresslane_cffi`
library with its own header.

## Features
```

Apply this via a direct string replacement of the `## Features` line's
preceding blank line, inserting the new section above it — the rest of the
file (`## Features` onward) is unchanged.

- [ ] **Step 5: Verify CI steps locally**

Run: `cc -I lightway-expresslane-cffi/include -Wall -Wextra -fsyntax-only -xc - <<'EOF'
#include "lightway_expresslane_cffi.h"
int main(void) { return 0; }
EOF`
Expected: no output, exit code 0.

Run: `c++ -I lightway-expresslane-cffi/include -Wall -Wextra -fsyntax-only -xc++ - <<'EOF'
#include "lightway_expresslane_cffi.h"
int main(void) { return 0; }
EOF`
Expected: no output, exit code 0.

Run: `cargo build && git diff --exit-code include/lightway_cffi.h lightway-expresslane-cffi/include/lightway_expresslane_cffi.h`
Expected: no diff (headers already committed and up to date from Task 10/11/12 commits).

Run: `cargo clippy --workspace -- -D warnings`
Expected: no warnings across all three crates (this catches any missing `# Safety` doc, missing `///` doc comment, or undocumented `unsafe` block introduced in earlier tasks).

- [ ] **Step 6: Commit**

```bash
jj commit -m "expresslane-cffi: wire CI header checks, add README"
```

---

## Post-plan verification

After Task 13, run the full suite once more from the repo root to confirm everything is green together:

```bash
cargo build --release
cargo test
cargo clippy --workspace -- -D warnings
```

Expected: all three crates build in release mode, every test across the workspace passes, and clippy is clean.

Then use the `superpowers:finishing-a-development-branch` skill to decide how to integrate this work (the jj changesets created by this plan's `jj commit` steps).
