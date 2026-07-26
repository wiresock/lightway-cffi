//! Bakes build provenance into the exe.
//!
//! The exe is built on a dev box and carried to a bare test box, so the report
//! has to describe its own build or the operator has to remember to. A number
//! whose toolchain and profile are unknown is not comparable to M1's.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let version = std::process::Command::new(rustc)
        .arg("-V")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=M3_RUSTC={version}");
    println!(
        "cargo:rustc-env=M3_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
    // `PROFILE` is NOT the profile name — cargo sets it to "release" for every
    // profile that inherits `release`, so a `--profile lto` exe would announce
    // itself as `release` and its fat-LTO / cgu-1 numbers would be subtracted
    // from M1's non-LTO 7.66. The profile *directory* is the real name, and it
    // is the 4th path component from the end of OUT_DIR:
    //   <target>/[<triple>/]<profile>/build/<pkg>-<hash>/out
    let profile = std::env::var("OUT_DIR")
        .ok()
        .and_then(|d| {
            std::path::Path::new(&d)
                .parent() // <pkg>-<hash>
                .and_then(|p| p.parent()) // build
                .and_then(|p| p.parent()) // <profile>
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .map(str::to_string)
        })
        .or_else(|| std::env::var("PROFILE").ok())
        .unwrap_or_default();
    println!("cargo:rustc-env=M3_PROFILE={profile}");
    println!(
        "cargo:rustc-env=M3_OPT_LEVEL={}",
        std::env::var("OPT_LEVEL").unwrap_or_default()
    );
}
