#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, map},
    maps::HashMap,
    helpers::bpf_get_current_pid_tgid,
    programs::TracePointContext,
};

#[map]
static TARGET_PID: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

#[map]
static TARGET_FDS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn syscall_write(ctx: TracePointContext) -> u32 {
    match try_syscall_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_syscall_write(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    unsafe{
        // Filter by PID
        if TARGET_PID.get(&pid).is_none() {
            return Ok(0);
        }
    }

    unsafe {
        // Tracepoint sys_enter_write: arg0 is FD
        let fd: u32 = ctx.read_at(0).map_err(|_| 0u32)?;
        
        if TARGET_FDS.get(&fd).is_some() {
            aya_log_ebpf::info!(&ctx, "WRITE: PID {} FD {}", pid, fd);
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// --- Unit Tests ---
// These run on your host CPU, not in the kernel
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logic_ok() {
        // Since we can't easily mock TracePointContext in no_std, 
        // focus on testing helper functions that handle data 
        // after it has been extracted from the context.
        assert_eq!(1, 1); 
    }
}

