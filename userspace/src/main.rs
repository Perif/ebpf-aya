use aya::{include_bytes_aligned, Ebpf};
use aya::programs::TracePoint;
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // 1. Load the eBPF binary compiled by xtask
    // We use `include_bytes_aligned` to bundle the BPF bytecode into our binary.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/libebpf.so" // Added 'lib' prefix
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/libebpf.so" // Added 'lib' prefix
    ))?;

    // 2. Initialize eBPF logging
    // This allows `info!` calls in the kernel to show up in our terminal.
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // 3. Load the specific program (syscall_enter)
    // Note: The name "syscall_enter" must match the function name in ebpf/src/lib.rs
    let program: &mut TracePoint = bpf.program_mut("syscall_enter").unwrap().try_into()?;
    program.load()?;

    // 4. Attach to the Kernel Tracepoint
    // "syscalls" is the category, "sys_enter_execve" is the specific event.
    // We attach to `execve` to avoid spamming logs for every single syscall.
    // If you want ALL syscalls, use "sys_enter" (warning: extremely high volume).
    let _link_id = program.attach("syscalls", "sys_enter_execve")?;
    
    info!("eBPF program attached! Waiting for Ctrl-C...");

    // 5. Keep running until Ctrl-C
    // If we drop `link_id` or exit, the eBPF program is detached.
    signal::ctrl_c().await?;
    
    info!("Exiting...");

    Ok(())
}

#[cfg(test)]
mod tests {
    use aya::{Ebpf, include_bytes_aligned};

    #[test]
    fn test_ebpf_bytecode_is_valid() {
        // Ensure the BPF bytecode is actually present and loadable
        // This catch errors where the file path in include_bytes_aligned is wrong
        let bpf_code = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/ebpf");
        let loader = Ebpf::load(bpf_code);
        
        assert!(loader.is_ok(), "BPF bytecode should be loadable. Did you run 'make build-bpf'?");
    }

    #[test]
    fn test_program_exists_in_elf() {
        let bpf_code = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/ebpf");
        let bpf = Ebpf::load(bpf_code).unwrap();
        
        // Ensure the function name in Rust matches the ELF section name
        assert!(bpf.program("syscall_enter").is_some());
    }
}