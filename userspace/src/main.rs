use aya::{include_bytes_aligned, Ebpf};
use aya::programs::TracePoint;
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;
use aya::maps::HashMap;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long)]
    pid: u32,

    #[clap(short, long)]
    fds: Vec<u32>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    env_logger::init();

    // 1. Load the eBPF bytecode
    // Ensure this path matches your build output (likely 'ebpf' without .so)
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/libebpf.so"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/libebpf.so"
    ))?;

    // 2. Initialize Logging
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // 3. Configure PID filter
    // We use 0 as a dummy value to simulate a set
    let mut target_pid: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("TARGET_PID").unwrap())?;
    target_pid.insert(args.pid, 0, 0)?;

    // 4. Configure FD filter
    let mut target_fds: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("TARGET_FDS").unwrap())?;
    for fd in args.fds {
        target_fds.insert(fd, 0, 0)?;
        info!("Monitoring PID {} on FD {}", args.pid, fd);
    }

    // 5. Attach the Tracepoint
    let program: &mut TracePoint = bpf.program_mut("syscall_write").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_write")?;

    info!("Waiting for Ctrl-C...");
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