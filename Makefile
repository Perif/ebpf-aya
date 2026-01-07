# Variables
CARGO := cargo
XTASK := xtask
USER_APP := userspace

# Default build profile is debug. 
# Usage: make build RELEASE=1
PROFILE := debug
CARGO_FLAGS := 
XTASK_FLAGS := 

ifdef RELEASE
	PROFILE := release
	CARGO_FLAGS += --release
	XTASK_FLAGS += --release
endif

# Usage: make run PID=12345 FDS="1 2"
PID ?= 0
FDS ?=

# Targets that don't match filenames
.PHONY: all install-deps build build-bpf build-userspace run test clean help

# Default target
all: build

# --- Setup & Dependencies ---

# Install necessary tools
install-deps:
	@echo ">> Installing bpf-linker..."
	$(CARGO) install bpf-linker
	@echo ">> Installing Nightly Rust and src..."
	rustup toolchain install nightly
	rustup component add rust-src --toolchain nightly

# --- Build Steps ---

# Build everything (Kernel + User)
build: build-bpf build-userspace

# 1. Build the eBPF Kernel program
# This runs the xtask Rust program we created, which handles the complex BPF compilation
build-bpf:
	@echo ">> Building eBPF Bytecode..."
	$(CARGO) run --package $(XTASK) -- build $(XTASK_FLAGS)

# 2. Build the Userspace Agent
# Depends on the eBPF bytecode existing. We explicitly build it here to separate concerns.
build-userspace:
	@echo ">> Building Userspace Agent..."
	$(CARGO) build --package $(USER_APP) $(CARGO_FLAGS)

# --- Execution ---

# Run the application
# Note: sudo -E preserves the environment (needed for RUST_LOG to work)
run: build
		@echo ">> Running $(USER_APP) (sudo required)..."
		sudo -E RUST_LOG=info ./target/$(PROFILE)/$(USER_APP) --pid $(PID) $(foreach fd,$(FDS),--fds $(fd))

# --- Testing & Maintenance ---

# Read the global pipe
pipe:
	@echo ">> Reading the kernel pipe to listen to messages..."
	sudo cat /sys/kernel/debug/tracing/trace_pipe

# Run unit tests across the workspace
test:
	@echo ">> Running Workspace Tests..."
	$(CARGO) test --workspace
# Clean all artifacts
clean:
	@echo ">> Cleaning build artifacts..."
	$(CARGO) clean

# Help Menu
help:
	@echo "Available commands:"
	@echo "  make install-deps    - Install bpf-linker and rust-src"
	@echo "  make build           - Build both kernel and user space code (Debug)"
	@echo "  make build RELEASE=1 - Build for Release"
	@echo "  make run             - Build and run the agent (requires sudo)"
	@echo "  make test            - Run cargo tests"
	@echo "  make clean           - Clean all build artifacts"
