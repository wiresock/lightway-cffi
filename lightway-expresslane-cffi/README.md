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
