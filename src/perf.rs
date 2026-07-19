//! Open `PERF_COUNT_SW_CPU_CLOCK` perf events at a given frequency and
//! attach a loaded BPF program to them on every CPU.

use anyhow::{anyhow, Result};
use libc::{c_int, pid_t};

const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

// perf_event_attr bit layout (Linux UAPI). We only set the fields the kernel
// strictly needs for a frequency-driven BPF-attached software event.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events_or_watermark: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    __reserved2: u16,
}

/// Open a per-CPU software CPU-clock event at the requested frequency.
pub fn open_cpu_clock(freq: u64, cpu: i32, exclude_kernel: bool) -> Result<c_int> {
    let attr = PerfEventAttr {
        type_: PERF_TYPE_SOFTWARE,
        size: std::mem::size_of::<PerfEventAttr>() as u32,
        config: PERF_COUNT_SW_CPU_CLOCK,
        sample_period_or_freq: freq,
        flags: (1u64 << 10) | (u64::from(exclude_kernel) << 5),
        ..Default::default()
    };

    let pid: pid_t = -1; // cpu-wide; BPF filters by targ_pid
    let group_fd: c_int = -1;

    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const PerfEventAttr,
            pid,
            cpu,
            group_fd,
            0u64,
        )
    };
    if fd < 0 {
        return Err(anyhow!(
            "perf_event_open(cpu={cpu}, freq={freq}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd as c_int)
}
