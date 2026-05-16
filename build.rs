//! Build script: regenerate `include/lightway_cffi.h` from the crate's
//! `extern "C"` surface using cbindgen.
//!
//! The header is committed to the repo (under `include/`) so consumers can
//! rely on it without running `cargo build` first; this build script keeps
//! it in sync with the Rust sources during development.

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("cbindgen.toml");
    let out_header = crate_dir.join("include").join("lightway_cffi.h");

    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");

    // Skip header generation when building from a read-only source tree
    // (e.g. published crate, vendored build).
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
            // Don't fail the build just because cbindgen couldn't regenerate
            // the header (e.g. network-free CI on a fresh checkout); emit a
            // warning and carry on so `cargo build` still produces the .lib.
            println!("cargo:warning=cbindgen failed to regenerate header: {e}");
        }
    }
}
