# Rust eBPF Monitor

A system observability tool built with the **Aya** library and **Tokio**. This project monitors kernel-level `execve` system calls using eBPF tracepoints, providing real-time visibility into process execution across the operating system.

---

## Project Architecture

The project is organized into three distinct Rust packages within a workspace:

* **`ebpf`**: The kernel-space program. It runs within the Linux kernel's eBPF virtual machine.
* **`userspace`**: The control plane. It loads the eBPF bytecode, attaches it to kernel hooks, and streams logs.
* **`xtask`**: A build utility that automates the compilation of Rust code into BPF bytecode using `bpf-linker`.

---

## Prerequisites

The following dependencies must be installed on the host system:

* **Rust Nightly**: Required for `no_std` BPF compilation.
* **bpf-linker**: Links LLVM bitcode into a BPF ELF file.
* **Linux Kernel**: Version 5.4 or newer is recommended for full tracepoint support.

```bash
make install-deps