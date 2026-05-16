//! Versioning helpers for the C ABI.
//!
//! We keep the returned strings as `&'static CStr` so callers can just
//! read them without ownership concerns.

use std::ffi::CStr;
use std::sync::OnceLock;

// The `LIGHTWAY_BUILD_ID` env var can be set by the build pipeline.
// Falls back to "dev" for local builds.
const BUILD_ID: &str = match option_env!("LIGHTWAY_BUILD_ID") {
    Some(b) => b,
    None => "dev",
};

/// NUL-terminated byte slice for [`crate::he_lightway_version`].
#[doc(hidden)]
pub(crate) static LIGHTWAY_VERSION_CSTR: LazyCStr = LazyCStr::new(|| compose_nul(BUILD_ID));

/// NUL-terminated byte slice for [`crate::he_wolfssl_version`].
#[doc(hidden)]
pub(crate) static WOLFSSL_VERSION_CSTR: LazyCStr = LazyCStr::new(|| {
    compose_nul(&lightway_core::tls::get_version_string())
});

/// Copy `s` into a freshly allocated `Box<str>` with a trailing NUL.
fn compose_nul(s: &str) -> Box<str> {
    let mut out = String::with_capacity(s.len() + 1);
    out.push_str(s);
    out.push('\0');
    out.into_boxed_str()
}

/// A `&'static CStr` computed lazily from a `Box<str>` whose last byte is
/// known to be `\0`. The `Box<str>` is leaked so the pointer stays valid
/// for the rest of the process.
#[doc(hidden)]
pub(crate) struct LazyCStr {
    inner: OnceLock<&'static CStr>,
    init: fn() -> Box<str>,
}

impl LazyCStr {
    pub(crate) const fn new(init: fn() -> Box<str>) -> Self {
        Self {
            inner: OnceLock::new(),
            init,
        }
    }

    pub(crate) fn as_ptr(&self) -> *const std::ffi::c_char {
        self.get().as_ptr()
    }

    fn get(&self) -> &'static CStr {
        self.inner.get_or_init(|| {
            let boxed = (self.init)();
            let leaked: &'static str = Box::leak(boxed);
            // SAFETY: `init` guarantees the last byte is `\0` and no interior NULs.
            unsafe { CStr::from_bytes_with_nul_unchecked(leaked.as_bytes()) }
        })
    }
}
