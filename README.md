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

- Full Lightway client connection lifecycle (`he_client_create`, `he_client_connect`, …)
- ExpressLane fast-path support — key-material callback and state-change callback
- ChaCha20 cipher selection
- Post-quantum key exchange — `he_ssl_ctx_set_use_pqc(ctx, true)` offers a PQC
  key-share group (`P521MLKEM1024`) during the TLS handshake
- Thread-safe: concurrent `he_conn_outside_data_received` / `he_conn_inside_packet_received` /
  `he_conn_nudge` calls are serialised internally. Re-entrant calls into a locking API from
  within a C callback are rejected with `HE_ERR_INVALID_CONN_STATE` rather than dead-locking.
- Panics from `lightway-core` / wolfSSL or from C callbacks are contained at the FFI boundary
  (returned as `HE_ERR_FAILED`) instead of aborting the process.

## Threading model

What is and isn't serialised is deliberately narrow:

- **Serialised:** the data-path calls `he_conn_outside_data_received`,
  `he_conn_inside_packet_received` and `he_conn_nudge`, plus `he_client_connect` /
  `he_client_disconnect` / `he_conn_get_session_id`. These may be called from multiple threads;
  the library serialises them on a per-client lock. Re-entering one from within a callback is
  rejected with `HE_ERR_INVALID_CONN_STATE`.
- **NOT serialised:** the configuration setters (`he_conn_set_*`, `he_ssl_ctx_set_*`) and the
  plain getters (`he_conn_get_outside_mtu`, `…_cipher_name`, etc.) touch the client without the
  lock. Configure the client from a single thread before `he_client_connect`, and read getters
  after `HE_STATE_ONLINE` (by which point their values are fixed).
- **`he_client_destroy` is not serialised at all.** The caller must ensure every thread that
  could call into this client has quiesced before destroying it; destroying while a data-path
  call is in flight (or calling the data path after destroy) is a use-after-free.

## Limitations

- **Post-quantum crypto:** enabling PQC selects a single key-share group
  (`P521MLKEM1024`, the reference `lightway-client` default and the server's
  preferred group); the C API does not yet expose per-connection group
  selection.
- **PMTUD:** Path MTU Discovery is not driven by this shim. The PMTUD callback setters and
  `he_conn_get_effective_pmtu` are retained for ABI compatibility but the callbacks never fire
  and the effective PMTU is always reported as `0`.
- **Threat-manager / packet filter:** `he_packet_filter_t` / `he_domain_filter_t` are provided by
  the C consumer (`common/threat-manager/packet_filter.h`), not by this crate.
- **Server-role callbacks** (`he_ssl_ctx_set_auth_cb`, `…_auth_token_cb`, `…_auth_buf_cb`,
  `…_populate_network_config_ipv4_cb`) are accepted for source compatibility but unused by this
  client-only shim.

## Building

```sh
# Debug build (also regenerates include/lightway_cffi.h via cbindgen)
cargo build

# Release build
cargo build --release

# Skip header regeneration (e.g. in a vendored / offline build)
LIGHTWAY_CFFI_SKIP_CBINDGEN=1 cargo build --release
```

The build produces:
- `target/release/lightway_cffi.dll` + `lightway_cffi.dll.lib` (Windows dynamic)
- `target/release/lightway_cffi.lib` (Windows static)
- `target/release/liblightway_cffi.so` (Linux dynamic)
- `target/release/liblightway_cffi.a` (Linux static)

## Linking

`lightway_cffi.lib` / `liblightway_cffi.a` is a Rust staticlib containing only
Rust object files. The Rust build system (`cargo`) also compiles **wolfSSL** from
source via the [`wolfssl-sys`](https://crates.io/crates/wolfssl-sys) crate and
produces a separate native static library. When cargo is the final linker (e.g.
`cargo build`) it links both automatically. When an **external build system**
(MSBuild, CMake, Make, …) is the final linker it must supply both libraries:

| Library | Location after `cargo build --release` |
|---|---|
| `lightway_cffi.lib` | `target/<triple>/release/` |
| `wolfssl.lib` | `target/<triple>/release/build/wolfssl-sys-*/out/wolfssl-src/Release/<arch>/wolfssl.lib` |

On Linux the wolfSSL archive is named `libwolfssl.a` and lives under
`target/<triple>/release/build/wolfssl-sys-*/out/`.

### Example: MSBuild (Windows)

```xml
<AdditionalDependencies>lightway_cffi.lib;wolfssl.lib;userenv.lib;...</AdditionalDependencies>
```

Both libraries must be on the `AdditionalLibraryDirectories` path, or copy them
to a common directory first. The `lightway-cffi.cmd` helper script in
`kp_pkf_client` automates this.

## Header

`include/lightway_cffi.h` is auto-generated by [cbindgen](https://github.com/mozilla/cbindgen)
and committed to the repository so consumers do not need a Rust toolchain.
After any change to the public `extern "C"` surface, run `cargo build` and
commit the updated header.

## Dependency

`lightway-core` is pulled directly from the public GitHub repository:

```toml
lightway-core = { git = "https://github.com/expressvpn/lightway", rev = "...", features = ["postquantum"] }
```

No private code is required. ExpressLane and post-quantum key exchange are both
fully supported in the open-source `lightway-core` crate. The `postquantum`
feature gates `lightway-core`'s `with_pq_crypto` API; wolfSSL itself is always
compiled with ML-KEM support (a default `wolfssl-sys` feature).

## API compatibility notes

The `he_*` naming convention mirrors the OSS `expressvpn/lightway-core` C
library. The following source-compatibility aliases are emitted at the bottom
of the header:

```c
typedef he_connection_type_t he_connection_type;
```

The threat-manager types (`he_packet_filter_t`, `he_domain_filter_t`) are
excluded from the generated header because `kp_pkf_client` defines them in
`common/threat-manager/packet_filter.h`. Define
`XV_LIGHTWAY_CFFI_NO_PACKET_FILTER_INCLUDE` before including the header to
suppress the automatic include of that file.

## License

AGPL-3.0-only — same as `lightway-core`.
