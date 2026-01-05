use std::process::Command;
use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the eBPF program
    Build {
        /// Build the release target
        #[clap(long)]
        release: bool,
    },
}

fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Build { release } => {
            build_ebpf(*release)
        }
    }
}

fn build_ebpf(release: bool) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("ebpf");
    let target = "bpfel-unknown-none";
    
    let mut args = vec![
        "build",
        "--target", target,
        "-Z", "build-std=core",
    ];

    if release {
        args.push("--release");
    }

    println!(">> Executing cargo build for eBPF...");
    let status = Command::new("cargo")
        .current_dir(dir)
        .arg("+nightly")
        .args(&args)
        .status()
        .expect("Failed to build eBPF package");

    if !status.success() {
        anyhow::bail!("Failed to build eBPF program");
    }

    Ok(())
}