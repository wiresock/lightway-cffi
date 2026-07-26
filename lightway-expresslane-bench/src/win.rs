//! Win32 timing primitives, declared inline.
//!
//! Cycles come from `QueryThreadCycleTime`, not `__rdtsc`, for the same reason
//! M1's probe does (see `netlib/src/tools/perf_probe.h`): on modern x86 the TSC
//! is *invariant* — it advances at the nominal frequency no matter what the
//! core's real clock is doing — so an rdtsc-derived cycles/byte silently bakes
//! in an assumed frequency. M3's numbers have to be directly subtractable from
//! M1's 7.66 cycles/byte, which means the same clock source. Dividing consumed
//! cycles by CPU time from `GetThreadTimes` also makes the sustained effective
//! frequency a measured output, checkable against M1's 4.02 GHz.
//!
//! Declared with a bare `unsafe extern "system"` block rather than `windows-sys`
//! so the dependency graph stays at three crypto crates and the exe stays
//! trivially self-contained for the walk over to the test box.

#![allow(non_snake_case)]

/// `FILETIME`. Two u32s rather than a u64 because the struct is not guaranteed
/// 8-byte aligned and the API takes it by pointer.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FileTime {
    pub lo: u32,
    pub hi: u32,
}

impl FileTime {
    pub fn as_100ns(self) -> u64 {
        ((self.hi as u64) << 32) | self.lo as u64
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThread() -> isize;
    fn GetCurrentProcess() -> isize;
    fn QueryThreadCycleTime(thread: isize, cycles: *mut u64) -> i32;
    fn GetThreadTimes(
        thread: isize,
        creation: *mut FileTime,
        exit: *mut FileTime,
        kernel: *mut FileTime,
        user: *mut FileTime,
    ) -> i32;
    fn GetSystemTimes(idle: *mut FileTime, kernel: *mut FileTime, user: *mut FileTime) -> i32;
    fn SetThreadAffinityMask(thread: isize, mask: usize) -> usize;
    fn SetThreadIdealProcessor(thread: isize, processor: u32) -> u32;
    fn GetCurrentProcessorNumber() -> u32;
    fn SetThreadPriority(thread: isize, priority: i32) -> i32;
    fn SetPriorityClass(process: isize, class: u32) -> i32;
    fn QueryPerformanceCounter(value: *mut i64) -> i32;
    fn QueryPerformanceFrequency(value: *mut i64) -> i32;
}

const HIGH_PRIORITY_CLASS: u32 = 0x0000_0080;
const THREAD_PRIORITY_HIGHEST: i32 = 2;
/// `MAXIMUM_PROCESSORS` on x64. `SetThreadIdealProcessor` is *zero-based*, so
/// this — not 0 — is the documented "clear the ideal processor" value.
const MAXIMUM_PROCESSORS: u32 = 64;

/// Abort on a failed measurement primitive.
///
/// The scheduling calls below (affinity, ideal processor, priority) are
/// best-effort tuning and are allowed to fail — the report states what actually
/// took effect. The *measurement* primitives are not: every one of them returns
/// a plausible-looking zero on failure, which would silently become a zero cycle
/// delta, a zero elapsed time, or an effective GHz of nothing. A benchmark whose
/// entire purpose is to keep a performance decision honest must not be able to
/// report a fabricated number, so these abort instead.
///
/// `#[cold]` and out of line so the check stays a predictably-not-taken branch;
/// `cycles()` runs twice per sample and its cost is itself measured and reported.
#[cold]
#[inline(never)]
fn win32_failed(api: &str) -> ! {
    panic!(
        "{api} failed (GetLastError not captured). Every measurement this run \
         would produce is meaningless, so it is aborted rather than reported."
    );
}

/// CPU cycles actually consumed by this thread. The measurement primitive.
#[inline]
pub fn cycles() -> u64 {
    let mut c = 0u64;
    // SAFETY: both arguments are valid; GetCurrentThread returns a pseudo-handle
    // that needs no cleanup.
    let ok = unsafe { QueryThreadCycleTime(GetCurrentThread(), &mut c) };
    if ok == 0 {
        win32_failed("QueryThreadCycleTime");
    }
    c
}

/// This thread's kernel + user CPU time, in 100 ns units.
///
/// Granularity is the scheduler tick (~15.6 ms at the default timer
/// resolution). It is therefore read **once around a whole arm-round block**
/// (hundreds of ms of contiguous CPU), never per sample: a sum of thousands of
/// sub-tick deltas accumulates quantization error instead of recovering the
/// total, and a fast arm can sum to literally zero. It exists solely as the
/// denominator for effective GHz and for the preemption detector, and the
/// caller must refuse to report either when too little time accumulated.
#[inline]
pub fn cpu_100ns() -> u64 {
    let (mut c, mut e, mut k, mut u) = (
        FileTime::default(),
        FileTime::default(),
        FileTime::default(),
        FileTime::default(),
    );
    // SAFETY: four valid out-pointers, pseudo-handle needs no cleanup.
    let ok = unsafe { GetThreadTimes(GetCurrentThread(), &mut c, &mut e, &mut k, &mut u) };
    if ok == 0 {
        win32_failed("GetThreadTimes");
    }
    k.as_100ns() + u.as_100ns()
}

/// Wall clock, for the preemption detector. A single-threaded non-blocking
/// loop should show wall time ≈ CPU time; a divergence means the thread was
/// descheduled and the sample is contaminated.
#[inline]
pub fn qpc() -> i64 {
    let mut v = 0i64;
    // SAFETY: valid out-pointer.
    let ok = unsafe { QueryPerformanceCounter(&mut v) };
    if ok == 0 {
        win32_failed("QueryPerformanceCounter");
    }
    v
}

pub fn qpc_freq() -> i64 {
    let mut v = 0i64;
    // SAFETY: valid out-pointer.
    let ok = unsafe { QueryPerformanceFrequency(&mut v) };
    // A zero frequency would divide into an infinite wall time and silently
    // disable the preemption detector, so treat it exactly like a failed call
    // rather than substituting 1 and carrying on.
    if ok == 0 || v <= 0 {
        win32_failed("QueryPerformanceFrequency");
    }
    v
}

/// System-wide (idle, kernel, user) CPU time in 100 ns units, for the
/// "was anything else running?" gate.
pub fn system_times() -> (u64, u64, u64) {
    let (mut i, mut k, mut u) = (
        FileTime::default(),
        FileTime::default(),
        FileTime::default(),
    );
    // SAFETY: three valid out-pointers.
    let ok = unsafe { GetSystemTimes(&mut i, &mut k, &mut u) };
    if ok == 0 {
        win32_failed("GetSystemTimes");
    }
    // GetSystemTimes' `kernel` figure INCLUDES idle, so busy = (k - i) + u.
    (i.as_100ns(), k.as_100ns(), u.as_100ns())
}

/// Which logical CPU this thread is executing on right now. Sampled at round
/// boundaries and reported as a set, so the "did it hop core classes?" question
/// the default (unpinned) mode raises is answerable from the report itself.
#[inline]
pub fn current_cpu() -> u32 {
    // SAFETY: no arguments, no handles.
    unsafe { GetCurrentProcessorNumber() }
}

/// Raise priority and (optionally) place the thread.
///
/// Deliberately unplaced by default rather than `SetThreadAffinityMask`. The
/// test box is a VM: pinning binds to a *virtual* CPU that the hypervisor may
/// still schedule anywhere, including a different core class on a hybrid host —
/// so hard pinning buys a false sense of control while risking an E-core
/// lock-in. `--pin N` is there for the bare-metal M1 rig, where it is real.
///
/// The default explicitly *clears* any ideal-processor preference rather than
/// requesting one. `SetThreadIdealProcessor` is zero-based, so asking for `0`
/// is a real request for logical CPU 0 — which on Windows is the default target
/// for timer interrupts and DPC work, i.e. precisely the worst core to measure
/// cycle counts on. `MAXIMUM_PROCESSORS` is the documented no-preference value.
///
/// HIGH rather than REALTIME on purpose: REALTIME can starve kernel threads and
/// distort the very box being measured.
pub fn set_scheduling(pin: Option<u32>) -> String {
    // SAFETY: pseudo-handles, plain scalar arguments.
    unsafe {
        SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
        match pin {
            Some(cpu) if cpu < 64 => {
                let prev = SetThreadAffinityMask(GetCurrentThread(), 1usize << cpu);
                if prev == 0 {
                    format!("process=HIGH thread=HIGHEST affinity=PIN {cpu} FAILED")
                } else {
                    format!("process=HIGH thread=HIGHEST affinity=pinned to CPU {cpu}")
                }
            }
            Some(cpu) => format!("process=HIGH thread=HIGHEST affinity=PIN {cpu} OUT OF RANGE"),
            None => {
                SetThreadIdealProcessor(GetCurrentThread(), MAXIMUM_PROCESSORS);
                "process=HIGH thread=HIGHEST affinity=none (no ideal-processor preference, \
                 not pinned)"
                    .to_string()
            }
        }
    }
}

/// Cost of one `cycles()` call, in nanoseconds. Measured, not assumed: the
/// timer is called twice per sample and has to be provably negligible against
/// the shortest arm rather than subtracted (subtracting a noisy constant just
/// moves the error around).
pub fn timer_cost_ns() -> f64 {
    const N: u32 = 20_000;
    let f = qpc_freq() as f64;
    let t0 = qpc();
    let mut sink = 0u64;
    for _ in 0..N {
        sink = sink.wrapping_add(cycles());
    }
    let t1 = qpc();
    std::hint::black_box(sink);
    ((t1 - t0) as f64 / f) * 1e9 / N as f64
}
