//! CPU identity, ISA extensions and cache geometry.
//!
//! All three are load-bearing for interpreting the result, not decoration:
//!
//! - **Extensions.** `aes-gcm` selects AES-NI and PCLMULQDQ at *runtime* via
//!   CPUID (the `cpufeatures` crate), not at compile time, and `ring` picks
//!   between four AES-GCM implementations the same way — its fastest is gated
//!   on VAES + VPCLMULQDQ + AVX2. A ring number measured on a VAES box does not
//!   transfer to a box without it, and the difference is large. If this line is
//!   missing from a report, the ring figure cannot be interpreted at all.
//! - **Identity.** M1's 7.66 cycles/byte and 4.02 GHz belong to one specific
//!   rig. Substituting a measurement taken on a different CPU into them is
//!   arithmetic, not evidence.
//! - **Caches.** The cold arm is only "cold" if its working set actually
//!   exceeds the private caches. On a large server part 16 MiB may still sit in
//!   L3, in which case the cold arm is a lower bound and must say so.

use std::arch::x86_64::{__cpuid, __cpuid_count};

pub struct CpuInfo {
    pub brand: String,
    pub vendor: String,
    pub aes: bool,
    pub pclmulqdq: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub vaes: bool,
    pub vpclmulqdq: bool,
    pub sse41: bool,
    pub hypervisor: bool,
    /// L1d, L2, L3 in KiB; `None` where CPUID did not report one.
    pub l1d_kib: Option<u32>,
    pub l2_kib: Option<u32>,
    pub l3_kib: Option<u32>,
}

fn regs_to_bytes(out: &mut Vec<u8>, r: [u32; 4]) {
    for w in r {
        out.extend_from_slice(&w.to_le_bytes());
    }
}

pub fn detect() -> CpuInfo {
    // SAFETY: CPUID is unconditionally available on x86_64; every leaf used
    // here is first checked against the reported maximum leaf.
    unsafe {
        let leaf0 = __cpuid(0);
        let mut vendor = Vec::new();
        regs_to_bytes(&mut vendor, [leaf0.ebx, leaf0.edx, leaf0.ecx, 0]);
        vendor.truncate(12);
        let vendor = String::from_utf8_lossy(&vendor).to_string();

        let leaf1 = __cpuid(1);
        let hypervisor = leaf1.ecx & (1 << 31) != 0;

        let ext_max = __cpuid(0x8000_0000).eax;
        let brand = if ext_max >= 0x8000_0004 {
            let mut b = Vec::new();
            for leaf in 0x8000_0002u32..=0x8000_0004 {
                let r = __cpuid(leaf);
                regs_to_bytes(&mut b, [r.eax, r.ebx, r.ecx, r.edx]);
            }
            String::from_utf8_lossy(&b)
                .trim_end_matches('\0')
                .trim()
                .to_string()
        } else {
            "unknown".to_string()
        };

        // VAES (ECX bit 9) and VPCLMULQDQ (ECX bit 10) of leaf 7 subleaf 0 are
        // read straight from CPUID rather than through is_x86_feature_detected!,
        // to keep this compiling on any toolchain regardless of when those
        // feature *names* were stabilised in std.
        let (vaes, vpclmulqdq) = if leaf0.eax >= 7 {
            let l7 = __cpuid_count(7, 0);
            (l7.ecx & (1 << 9) != 0, l7.ecx & (1 << 10) != 0)
        } else {
            (false, false)
        };

        let (l1d_kib, l2_kib, l3_kib) = cache_sizes(leaf0.eax, ext_max, &vendor);

        CpuInfo {
            brand,
            vendor,
            // These names are long-stable in std and are the same CPUID checks
            // `cpufeatures` performs, so they are a valid proxy for which
            // backend aes-gcm selected.
            aes: is_x86_feature_detected!("aes"),
            pclmulqdq: is_x86_feature_detected!("pclmulqdq"),
            avx: is_x86_feature_detected!("avx"),
            avx2: is_x86_feature_detected!("avx2"),
            avx512f: is_x86_feature_detected!("avx512f"),
            vaes,
            vpclmulqdq,
            sse41: is_x86_feature_detected!("sse4.1"),
            hypervisor,
            l1d_kib,
            l2_kib,
            l3_kib,
        }
    }
}

/// Deterministic cache parameters. Leaf 4 on Intel; AMD reports the same
/// encoding on leaf 0x8000001D. Best effort — a `None` is printed as unknown
/// rather than guessed, because the cold-arm interpretation depends on it.
///
/// # Safety
/// Caller must have verified the leaves are supported.
unsafe fn cache_sizes(max_leaf: u32, ext_max: u32, vendor: &str) -> (Option<u32>, Option<u32>, Option<u32>) {
    let leaf = if vendor.starts_with("Auth") && ext_max >= 0x8000_001D {
        0x8000_001D
    } else if max_leaf >= 4 {
        4
    } else {
        return (None, None, None);
    };

    let (mut l1d, mut l2, mut l3) = (None, None, None);
    for sub in 0u32..16 {
        // `__cpuid_count` is a safe intrinsic on x86_64 (CPUID is
        // unconditionally available); the leaf was validated against the
        // reported maximum above so the *result* is meaningful, not just sound.
        let r = __cpuid_count(leaf, sub);
        let ctype = r.eax & 0x1F;
        if ctype == 0 {
            break; // no more cache levels
        }
        let level = (r.eax >> 5) & 0x7;
        let line = (r.ebx & 0xFFF) + 1;
        let parts = ((r.ebx >> 12) & 0x3FF) + 1;
        let ways = ((r.ebx >> 22) & 0x3FF) + 1;
        let sets = r.ecx + 1;
        let kib = (line as u64 * parts as u64 * ways as u64 * sets as u64 / 1024) as u32;
        match (level, ctype) {
            (1, 1) => l1d = Some(kib), // level 1, data
            (2, _) => l2 = Some(kib),
            (3, _) => l3 = Some(kib),
            _ => {}
        }
    }
    (l1d, l2, l3)
}

impl CpuInfo {
    pub fn feature_line(&self) -> String {
        let b = |v: bool| if v { 1 } else { 0 };
        format!(
            "aes={} pclmulqdq={} sse4.1={} avx={} avx2={} avx512f={} vaes={} vpclmulqdq={}",
            b(self.aes),
            b(self.pclmulqdq),
            b(self.sse41),
            b(self.avx),
            b(self.avx2),
            b(self.avx512f),
            b(self.vaes),
            b(self.vpclmulqdq)
        )
    }

    /// Which AES-GCM implementation ring will have selected. Printed so the
    /// ring figure carries its own portability caveat.
    pub fn ring_aes_path(&self) -> &'static str {
        if self.vaes && self.vpclmulqdq && self.avx2 {
            "VAES+VPCLMULQDQ+AVX2 (ring's fastest path)"
        } else if self.aes && self.pclmulqdq && self.avx {
            "AES-NI+CLMUL+AVX (ring's mid path - slower than VAES)"
        } else if self.aes && self.pclmulqdq {
            "AES-NI+CLMUL (ring's baseline hardware path)"
        } else {
            "NO HARDWARE AES - result is meaningless for provider comparison"
        }
    }
}
