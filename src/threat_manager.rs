//! Threat-manager / packet-filter types.
#![allow(
    non_camel_case_types,
    non_upper_case_globals,
    clippy::upper_case_acronyms,
    dead_code
)]
//!
//! `lightway_tunnel.h` uses two related objects:
//!
//! * `he_domain_filter_t` – a DNS-domain block/allow-list filter.
//! * `he_packet_filter_t` – a generic inline packet-filter hook embedded
//!   inside `he_domain_filter_t` (accessed as `&domain_filter->filter`).
//!
//! The C code pattern is:
//! ```c
//! he_domain_filter_t* df = he_domain_filter_new();
//! he_domain_filter_set_blocking_mode(df, HE_DOMAIN_FILTER_BLOCKING_MODE_NXDOMAIN);
//! he_domain_filter_block_domains_from_file(df, path);
//! he_packet_filter_t* pf = &df->filter;
//! he_packet_filter_set_context(pf, ctx);
//! he_packet_filter_set_write_cb(pf, write_cb);
//! // … then in the outbound path:
//! pf->handler(pf, ip_bytes, length); // => HE_PACKET_FILTER_DECISION_*
//! ```

use std::collections::HashSet;
use std::ffi::{CStr, c_char, c_void};

use crate::types::{he_domain_filter_blocking_mode_t, he_packet_filter_decision_t};

// ──────────────────────────────────────────────────────────────────────────────
// Packet-filter write callback
// ──────────────────────────────────────────────────────────────────────────────

/// Callback invoked by the domain filter to write a synthesised DNS reply back
/// into the inside (TUN) path.
pub type he_packet_filter_write_cb_t = unsafe extern "C" fn(
    filter: *mut he_packet_filter_t,
    context: *mut c_void,
    packet: *mut u8,
    length: usize,
);

/// Callback function pointer for packet inspection.
///
/// Implementations examine the raw IPv4 payload and return a
/// `he_packet_filter_decision_t` indicating whether to pass or block.
pub type he_packet_filter_handler_t = unsafe extern "C" fn(
    filter: *mut he_packet_filter_t,
    packet: *const u8,
    length: usize,
) -> he_packet_filter_decision_t;

// ──────────────────────────────────────────────────────────────────────────────
// he_packet_filter_t
// ──────────────────────────────────────────────────────────────────────────────

/// Generic inline packet-filter hook.
///
/// This struct is embedded at the **beginning** of `he_domain_filter_t` so
/// that C code can obtain a `he_packet_filter_t*` via `&domain_filter->filter`
/// and call `filter->handler(filter, packet, length)`.
#[repr(C)]
pub struct he_packet_filter_t {
    /// Packet inspection callback, set by the domain-filter implementation.
    pub handler: Option<he_packet_filter_handler_t>,
    /// Write-back callback set by the tunnel via `he_packet_filter_set_write_cb`.
    pub(crate) write_cb: Option<he_packet_filter_write_cb_t>,
    /// Opaque context pointer set by the tunnel via `he_packet_filter_set_context`.
    pub(crate) context: *mut c_void,
}

// SAFETY: context is a raw pointer managed entirely by C callers.
unsafe impl Send for he_packet_filter_t {}
unsafe impl Sync for he_packet_filter_t {}

// ──────────────────────────────────────────────────────────────────────────────
// he_domain_filter_t
// ──────────────────────────────────────────────────────────────────────────────

/// DNS domain block/allow-list filter.
///
/// The `filter` field **must** be first so that `&domain_filter->filter`
/// yields a valid `he_packet_filter_t*` for C code that only holds the
/// embedded filter pointer.
#[repr(C)]
pub struct he_domain_filter_t {
    /// Embedded packet-filter hook (must be first field).
    pub filter: he_packet_filter_t,

    // Internal state (not exposed to C directly)
    pub(crate) blocking_mode: he_domain_filter_blocking_mode_t,
    pub(crate) blocked_domains: HashSet<String>,
    pub(crate) allowed_domains: HashSet<String>,
}

impl he_domain_filter_t {
    pub(crate) fn new() -> Self {
        let mut df = Self {
            filter: he_packet_filter_t {
                handler: Some(domain_filter_handler),
                write_cb: None,
                context: std::ptr::null_mut(),
            },
            blocking_mode: he_domain_filter_blocking_mode_t::HE_DOMAIN_FILTER_BLOCKING_MODE_NXDOMAIN,
            blocked_domains: HashSet::new(),
            allowed_domains: HashSet::new(),
        };
        // The handler needs a pointer back to the owning he_domain_filter_t.
        // We set it after allocation in he_domain_filter_new() so the pointer
        // is stable (Box-allocated).
        df.filter.context = std::ptr::null_mut();
        df
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Domain-filter packet handler
// ──────────────────────────────────────────────────────────────────────────────

/// The `he_packet_filter_handler_t` installed by `he_domain_filter_t`.
///
/// Parses a raw IPv4/UDP/DNS payload and returns BLOCK if the queried domain
/// is in the blocked list (and not in the allow list).
///
/// # Safety
/// `filter` must point to the `he_packet_filter_t` embedded at offset 0 of a
/// valid, live `he_domain_filter_t`.  `packet` must point to `length` readable
/// bytes of an IPv4 packet.
unsafe extern "C" fn domain_filter_handler(
    filter: *mut he_packet_filter_t,
    packet: *const u8,
    length: usize,
) -> he_packet_filter_decision_t {
    if filter.is_null() || packet.is_null() || length == 0 {
        return he_packet_filter_decision_t::HE_PACKET_FILTER_DECISION_PASS;
    }

    // SAFETY: filter is the first field of he_domain_filter_t, so casting is
    // valid when called through the public C API which always passes the
    // embedded &df->filter pointer.
    let df = unsafe { &*(filter as *const he_domain_filter_t) };

    // Parse enough of the DNS payload to extract the queried name.
    let bytes = unsafe { std::slice::from_raw_parts(packet, length) };
    if let Some(name) = extract_dns_query_name(bytes) {
        // Check allow-list first — allowed domains are never blocked.
        if df.allowed_domains.contains(&name) {
            return he_packet_filter_decision_t::HE_PACKET_FILTER_DECISION_PASS;
        }
        if df.blocked_domains.contains(&name) {
            return he_packet_filter_decision_t::HE_PACKET_FILTER_DECISION_BLOCK;
        }
        // Check suffix matches (e.g. "ads.example.com" blocked by "example.com")
        for blocked in &df.blocked_domains {
            if name.ends_with(blocked.as_str())
                && name.len() > blocked.len()
                && name.as_bytes()[name.len() - blocked.len() - 1] == b'.'
            {
                return he_packet_filter_decision_t::HE_PACKET_FILTER_DECISION_BLOCK;
            }
        }
    }

    he_packet_filter_decision_t::HE_PACKET_FILTER_DECISION_PASS
}

// ──────────────────────────────────────────────────────────────────────────────
// DNS name parsing helper
// ──────────────────────────────────────────────────────────────────────────────

/// Attempt to parse the QNAME from a raw IPv4 UDP DNS query packet.
///
/// Returns `None` if the packet is too short, malformed, or not a DNS query.
fn extract_dns_query_name(ip_bytes: &[u8]) -> Option<String> {
    // Minimum: 20 (IP) + 8 (UDP) + 12 (DNS header) = 40 bytes
    if ip_bytes.len() < 40 {
        return None;
    }
    let ip_hl = ((ip_bytes[0] & 0x0F) as usize) * 4;
    if ip_hl < 20 || ip_bytes.len() <= ip_hl + 8 + 12 {
        return None;
    }
    // Protocol must be UDP (17)
    if ip_bytes[9] != 17 {
        return None;
    }
    // Skip IP + UDP headers; DNS starts at ip_hl + 8
    let dns = &ip_bytes[ip_hl + 8..];

    // QR bit (bit 15 of flags word) must be 0 for a query
    if dns.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    if flags & 0x8000 != 0 {
        return None; // response, not query
    }
    let qd_count = u16::from_be_bytes([dns[4], dns[5]]);
    if qd_count == 0 {
        return None;
    }

    // Parse the QNAME label sequence starting at offset 12
    let mut off = 12usize;
    let mut labels: Vec<&[u8]> = Vec::new();
    loop {
        if off >= dns.len() {
            return None;
        }
        let len = dns[off] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer — skip; we don't follow pointers in queries
            return None;
        }
        off += 1;
        if off + len > dns.len() {
            return None;
        }
        labels.push(&dns[off..off + len]);
        off += len;
    }

    let name = labels
        .iter()
        .map(|l| std::str::from_utf8(l).unwrap_or("").to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(".");
    if name.is_empty() { None } else { Some(name) }
}

// ──────────────────────────────────────────────────────────────────────────────
// Domain-list file loader
// ──────────────────────────────────────────────────────────────────────────────

/// Load NUL-terminated domain names (one per line, `#` comment lines skipped)
/// from a file and insert them into `set`.
///
/// Returns the number of entries added, or `-1` on I/O / parse error.
pub(crate) fn load_domains_from_file(path: *const c_char, set: &mut HashSet<String>) -> i32 {
    if path.is_null() {
        return -1;
    }
    let c_str = unsafe { CStr::from_ptr(path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let content = match std::fs::read_to_string(path_str) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let mut count = 0i32;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        set.insert(trimmed.to_ascii_lowercase());
        count += 1;
    }
    count
}
