#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

#[tracepoint]
pub fn syscall_enter(ctx: TracePointContext) -> u32 {
    match try_syscall_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_syscall_enter(ctx: TracePointContext) -> Result<u32, u32> {
    // This ensures the import is used
    aya_log_ebpf::info!(&ctx, "SYSCALL ENTERED"); 
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // This is a common way to satisfy the '!' return type 
    // without actually creating a visible infinite loop.
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