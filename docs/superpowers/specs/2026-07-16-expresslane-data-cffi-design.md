# ExpressLane Data-Plane CFFI — Design

Date: 2026-07-16

## Problem

ExpressLane packet encrypt/decrypt today only happens inside `lightway-core`'s
`Connection`, driven by the inside/outside IO loop. There's no way to do
ExpressLane packet crypto out-of-process. The goal is to let external code —
starting with a Windows usermode service/process, later possibly a
kernel-mode driver (WFP callout / NDIS filter) — encrypt/decrypt individual
ExpressLane data packets directly, without linking the full `Connection` /
TLS / IO-loop machinery.

Key exchange and rotation timing (the `ExpresslaneConfig` frame, driven over
the TLS control channel) stay exactly where they are today, in
`lightway-core`'s `Connection`. This design is scoped to the data-plane
packet crypto only.

## Non-goals

- Key rotation timing/ack logic — stays in `lightway-core` Connection + TLS
  control channel, unchanged.
- `ExpresslaneConfig` frame handling (key exchange over TLS) — untouched.
- How the external app learns about new keys — already solved by the
  existing `he_expresslane_cb_t` / `he_expresslane_state_change_cb_t`
  callbacks on the full `lightway-cffi` client. Out of scope here.
- True kernel-mode packaging (`no_std` attribute, `panic = "abort"`, IRQL
  constraints). Not needed now; the design already avoids the things that
  would block a kernel port later (see "Forward compatibility" below), so
  it's a cheap follow-up rather than part of this work.
- Any change to `lightway-core` or the main `expressvpn/lightway` repo. This
  work is entirely additive to the `lightway-cffi` repo.

## Two new crates, both in the `lightway-cffi` repo

Both are new workspace members alongside the existing `lightway-cffi` crate.

### 1. `lightway-expresslane`

Pure Rust, no TLS/wolfssl dependency. An **independent reimplementation** of
the ExpressLane data-packet protocol — not extracted from `lightway-core`.
`lightway-core`'s own `Connection`/wire code is untouched and keeps using
wolfssl-backed AES-256-GCM internally exactly as it does today.

Implements the same wire format and same state as
`lightway-core/src/wire/expresslane_data.rs` today:

- `ExpresslaneKey([u8; 32])`
- `ExpresslaneVersion { Unknown, Version1, Version2 }` (controls AAD layout:
  V2 binds the 16-bit flags field into the AAD, V1 doesn't)
- `ExpresslaneSession` — holds the 4-key rotation state
  (`current_self`/`next_self`/`current_peer`/`prev_peer`) and an 8192-bit
  (128 × u64) replay window, same semantics as `ReplayWindow` in
  `lightway-core` today: `would_reject()` is a non-mutating pre-check before
  paying the AEAD cost, `commit()` only runs after AEAD verification
  succeeds (this ordering matters — committing before verification is what
  let a forged huge counter poison the window in a bug fixed upstream).

Unlike `lightway-core`'s `ExpresslaneData`, the wire counter used on encrypt
is **caller-supplied**, not auto-incremented internally — see "Parallel
encrypt" below. This is the one behavioral difference from the upstream
implementation; everything else (wire format, AAD, replay window, rotation
state) matches exactly.

Wire format (unchanged, 40 bytes overhead):

```
Counter (8) | IV (12) | AuthTag (16) | DataLen (2) | Flags (2) | Ciphertext (DataLen)
```

AAD: V1 = `SessionID(8) || Counter(8)` (16 bytes). V2 = `SessionID(8) ||
Counter(8) || Flags(2)` (18 bytes).

Cipher: RustCrypto `aes-gcm` crate (not wolfssl), using
`encrypt_in_place_detached` / `decrypt_in_place_detached` — operates
in-place on a caller-provided `&mut [u8]`, no heap allocation internally.

Rust API:

```rust
pub struct ExpresslaneKey(pub [u8; 32]);

#[repr(u8)]
pub enum ExpresslaneVersion { Unknown = 0, Version1 = 1, Version2 = 2 }

pub enum ExpresslaneError {
    InsufficientData,
    InvalidData,       // AEAD/auth failure or malformed packet
    Replayed,
    KeyNotSet,
    InvalidKey,         // cipher init/set_key failure
}
pub type ExpresslaneResult<T> = Result<T, ExpresslaneError>;

pub struct ExpresslaneSession { /* private fields, see "Parallel encrypt" */ }

impl ExpresslaneSession {
    pub const WIRE_OVERHEAD: usize = 40;

    pub fn new(version: ExpresslaneVersion) -> Self;

    // --- TX domain: safe to call concurrently from multiple threads on the
    // same session (see "Parallel encrypt"). ---

    /// Lock-free (AtomicU64 fetch_add). Returns a counter value guaranteed
    /// unique for this session, for use in the next `encrypt()` call.
    pub fn reserve_counter(&self) -> u64;

    pub fn update_next_self_key(&self, key: ExpresslaneKey) -> ExpresslaneResult<()>;
    pub fn promote_self_key(&self);   // promotes staged next_self -> current_self
    pub fn packets_sent(&self) -> u64;

    /// `out` must be >= `WIRE_OVERHEAD + plain_text.len()`. Returns bytes written.
    /// `counter` must be unique for this session — use `reserve_counter()`
    /// unless the caller already has its own uniqueness guarantee.
    pub fn encrypt(
        &self,
        counter: u64,
        session_id: [u8; 8],
        plain_text: &[u8],
        iv: [u8; 12],
        is_encoded: bool,
        out: &mut [u8],
    ) -> ExpresslaneResult<usize>;

    // --- RX domain: serialized internally as a unit by the `rx` mutex, so
    // these are `&self` and safe to call from any thread (see "Parallel
    // encrypt"). Concurrent RX calls on one session simply take turns. ---

    pub fn has_valid_keys(&self) -> bool;
    pub fn update_peer_key(&self, key: ExpresslaneKey) -> ExpresslaneResult<()>;
    pub fn packets_received(&self) -> u64;

    /// `out` must be >= `wire_packet.len() - WIRE_OVERHEAD`. Returns (plaintext_len, is_encoded).
    pub fn decrypt(
        &self,
        session_id: [u8; 8],
        wire_packet: &[u8],
        out: &mut [u8],
    ) -> ExpresslaneResult<(usize, bool)>;
}
```

`session_id` is a plain `[u8; 8]`, not `lightway_core::wire::SessionId` —
this crate has no dependency on `lightway-core`.

All RX methods take `&self`; the receive-side state (`current_peer`,
`prev_peer`, `replay_window`) lives behind the `rx` mutex, so a `decrypt`
concurrent with `has_valid_keys` on one session is serialized rather than
undefined behavior. The mutex is uncontended in the intended single-RX-thread
deployment.

### 2. `lightway-expresslane-cffi`

C ABI wrapper over `lightway-expresslane`, path-dependency within the same
workspace. Own `cdylib` + `staticlib` artifacts, own generated header
(`include/lightway_expresslane_cffi.h`), own CI job. Deliberately does not
link wolfssl — that's the point of splitting it out.

```c
typedef struct he_expresslane_session_t he_expresslane_session_t;  // opaque

typedef enum {
    HE_EXPRESSLANE_VERSION_UNKNOWN = 0,
    HE_EXPRESSLANE_VERSION_1 = 1,
    HE_EXPRESSLANE_VERSION_2 = 2,
} he_expresslane_version_t;

typedef enum {
    HE_EXPRESSLANE_SUCCESS = 0,
    HE_EXPRESSLANE_ERR_NULL_POINTER = -1,
    HE_EXPRESSLANE_ERR_BUFFER_TOO_SMALL = -2,
    HE_EXPRESSLANE_ERR_INSUFFICIENT_DATA = -3,
    HE_EXPRESSLANE_ERR_INVALID_DATA = -4,
    HE_EXPRESSLANE_ERR_REPLAYED = -5,
    HE_EXPRESSLANE_ERR_KEY_NOT_SET = -6,
    HE_EXPRESSLANE_ERR_INVALID_KEY = -7,
    HE_EXPRESSLANE_ERR_PANIC = -8,
} he_expresslane_return_code_t;

he_expresslane_session_t *he_expresslane_session_create(he_expresslane_version_t version);
void he_expresslane_session_destroy(he_expresslane_session_t *session);

/* TX domain — safe to call concurrently, from any number of threads, on
 * the same session handle. `const` signals that safety property. */
uint64_t he_expresslane_reserve_counter(const he_expresslane_session_t *session);
he_expresslane_return_code_t he_expresslane_set_next_self_key(
    const he_expresslane_session_t *session, const uint8_t key[32]);
void he_expresslane_promote_self_key(const he_expresslane_session_t *session);
uint64_t he_expresslane_packets_sent(const he_expresslane_session_t *session);

he_expresslane_return_code_t he_expresslane_encrypt(
    const he_expresslane_session_t *session,
    uint64_t counter,
    const uint8_t session_id[8],
    const uint8_t *plain_text, size_t plain_text_len,
    const uint8_t iv[12],
    bool is_encoded,
    uint8_t *out, size_t out_capacity,
    size_t *out_len);

/* RX domain — serialized internally per session (const handle); safe to call
 * from any thread, concurrent RX calls simply take turns. */
he_expresslane_return_code_t he_expresslane_set_peer_key(
    const he_expresslane_session_t *session, const uint8_t key[32]);
bool he_expresslane_has_valid_keys(const he_expresslane_session_t *session);
uint64_t he_expresslane_packets_received(const he_expresslane_session_t *session);

he_expresslane_return_code_t he_expresslane_decrypt(
    const he_expresslane_session_t *session,
    const uint8_t session_id[8],
    const uint8_t *wire_packet, size_t wire_packet_len,
    uint8_t *out, size_t out_capacity,
    size_t *out_len,
    bool *is_encoded);

size_t he_expresslane_wire_overhead(void);   // 40 — avoids a magic constant on the C side
```

## Parallel encrypt

Encrypt throughput matters for the driver use case — a single caller-serialized
session handle would force all encryption onto one thread. Decrypt doesn't get
the same treatment: the replay-window bitmap update is inherently ordered, and
a single RX path per session is the common case, so RX calls are simply
serialized (internally) rather than parallelized.

`ExpresslaneSession` internally splits into two independently-synchronized
halves; every public method takes `&self` and the session is `Sync`:

- **TX state** — `current_self: RwLock<Option<Cipher>>`,
  `next_self: Mutex<Option<Cipher>>`, `wire_counter_high_watermark: AtomicU64`
  (backs `reserve_counter()` and `packets_sent()`). Many threads hold a read
  lock on `current_self` for `encrypt()` concurrently; `promote_self_key()`
  takes a brief write lock to swap in the staged key. `next_self` sees
  near-zero contention — rotation is driven by one control-plane thread
  processing `ExpresslaneConfig` acks.
- **RX state** — `current_peer`, `prev_peer`, `replay_window` — held as a
  unit behind an internal `Mutex` (`rx`). `decrypt()`, `update_peer_key()`,
  `has_valid_keys()`, `packets_received()` take the lock for the duration of
  the call, so RX calls from any thread are safe and simply take turns. The
  lock is uncontended in the intended single-RX-thread deployment; it exists
  so a stray concurrent RX call (or an RX call concurrent with TX through the
  C API's shared handle) is merely serialized rather than undefined behavior.
  An earlier draft kept these as plain unlocked fields with `&mut self` /
  caller-serialized access, but that contract is not expressible soundly
  through a shared C handle: a conforming caller running TX (`&`) concurrently
  with RX (`&mut`) on one session would be aliasing UB in Rust's memory model.

Consequence for the wire counter specifically: `lightway-core`'s
`ExpresslaneData::append_to_wire` auto-increments its counter as part of the
encrypt call, which only works because that call is already serialized by
the `Connection`'s single-threaded IO loop. This crate can't assume that, so
`encrypt()` takes an explicit `counter: u64` instead. `reserve_counter()`
(atomic fetch-add) gives callers a zero-effort way to get a
guaranteed-unique value per call, from any thread, without building their
own coordination — callers with their own per-flow sequence numbers can
supply those directly instead, as long as they guarantee uniqueness across
every thread encrypting on that session.

## Conventions

- **Buffers**: caller-owned only, on both sides of the Rust/C boundary. No
  `Vec`/`Box` crosses the FFI boundary; no matching `_free()` function needed.
  Caller passes an output buffer + capacity; functions write into it and
  report bytes written, or `HE_EXPRESSLANE_ERR_BUFFER_TOO_SMALL` if it
  doesn't fit. This works unchanged in kernel mode later.
- **IV**: caller-supplied on encrypt (matches `lightway-core`'s existing
  pattern where `Connection` generates the IV and passes it into
  `append_to_wire`). The crate itself has no RNG dependency. Caller is
  responsible for a fresh, unpredictable 12-byte IV per packet per key —
  reusing an (key, IV) pair breaks AES-GCM's security guarantees; the wire
  counter is authenticated via AAD but is not itself the nonce.
- **Key sync**: out of scope, per the "Non-goals" section. The external app
  gets key material from the existing `he_expresslane_cb_t` /
  `he_expresslane_state_change_cb_t` callbacks on the full client and pushes
  it into a `he_expresslane_session_t` via `set_next_self_key` /
  `promote_self_key` / `set_peer_key`. This mirrors `ExpresslaneData`'s
  existing 4-slot rotation state as-is — no new state machine.
- **Threading**: see "Parallel encrypt" above — TX calls (`encrypt`,
  `reserve_counter`, `update_next_self_key`, `promote_self_key`,
  `packets_sent`) are safe to call concurrently from multiple threads on one
  session handle, and RX calls (`decrypt`, `update_peer_key`,
  `has_valid_keys`, `packets_received`) are serialized internally per
  session, so every `he_expresslane_*` function is safe to call from any
  thread on a shared handle (the only caller obligation is around
  `he_expresslane_session_destroy`). Independent session handles never need
  coordination with each other.
- **Panics**: caught at each `extern "C"` function boundary (reuse the
  pattern already used in `lightway-cffi`), mapped to
  `HE_EXPRESSLANE_ERR_PANIC` rather than unwinding across the FFI boundary.

## Forward compatibility (usermode now, kernel-mode later)

Nothing in this design requires Rust heap allocation to cross the FFI
boundary, and `ExpresslaneSession`'s internal state (replay-window bitmap,
cipher objects) is fixed-size / stack-representable — no `Vec`/`Box`
internally either. Combined with the RustCrypto `aes-gcm` crate's
`no_std` support, a future kernel-mode port is realistically a
`#![no_std]` + `panic = "abort"` packaging change to `lightway-expresslane`,
not a redesign. That port is explicitly not part of this work.

## Accepted risk: implementation drift

`lightway-expresslane` reimplements the same protocol as
`lightway-core`'s `ExpresslaneData`, rather than sharing code with it. A bug
fix or protocol change to one won't automatically apply to the other.

Mitigation (implemented): pinned **golden wire vectors** in
`lightway-expresslane/tests/wire_vectors.rs`. A fixed
(key, session_id, counter, iv, plaintext, version) tuple is asserted to
produce an exact byte sequence, and that sequence is asserted to decrypt
back — so any drift in field layout, endianness, `is_encoded`/reserved flag
handling, or AAD construction fails CI. The vector is a concrete artifact
that can be cross-checked by hand against `lightway-core`'s output for the
same inputs.

Mitigation (follow-up, not yet implemented): a permanent cross-crate interop
test that encrypts via the full `he_conn_t` client (`lightway-cffi`) and
decrypts via `he_expresslane_session_t` (and vice versa). This needs a TLS
handshake harness because `lightway-core`'s `ExpresslaneData` /
`append_to_wire` are `pub(crate)` and only reachable through a live
`Connection`; it is tracked as a separate task. Until it lands, the golden
vectors above are the drift guard.

## Testing

- Unit tests port the ~20 existing `expresslane_data.rs` test cases
  (key rotation, replay window edge cases, AAD version negotiation,
  tampered-flags rejection, forged-packet-doesn't-poison-window) into
  `lightway-expresslane`, adapted to the new caller-buffer API shape. Same
  assertions, same coverage — logic is unchanged, only the cipher backend
  differs.
- New: cross-crate interop test described above, added to CI for both
  crates.
- New: concurrency test — a single `#[test]` spawns N threads (via
  `std::thread::scope`) that each call `reserve_counter()` + `encrypt()` on
  one shared session concurrently, asserts every counter value is unique
  and every resulting wire packet decrypts successfully on a
  single-threaded receiver with no replay rejections. Also covers
  `promote_self_key()` firing mid-stream without corrupting in-flight
  `encrypt()` calls.
- `lightway-expresslane-cffi`'s header gets the same `header-compiles`
  C/C++ compile-check CI job pattern already used for `lightway_cffi.h`.

## Open items for the implementation plan

- Exact crate directory names/paths within the `lightway-cffi` repo
  workspace.
- Whether `lightway-expresslane`'s unit tests get ported verbatim or
  rewritten against the new buffer-based API (recommend: rewritten,
  same assertions).
- CI job wiring for the new interop test (which repo it lives in, given
  it needs both `lightway-cffi` and `lightway-expresslane-cffi` built).
