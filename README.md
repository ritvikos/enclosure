# Enclosure

A low-level process isolation utility (similar to bubblewrap) to construct sandbox(ing)
environment(s). The security-model is caller-defined, the calling process (shell, daemon, 
container-manager) that constructs the CLI-args owns the security policy.

## Contributing

Contributions are welcome: bug fixes, new NS support, documentation, test-coverage.

1. Fork the repo and create a branch off `main`
2. Make your changes w/ a [conventional commit message and description](https://www.conventionalcommits.org/en/v1.0.0/)
3. Open a PR w/ a short description addressing the patch's _what_ and _why_

For architectural changes or if you're unsure where to start, opening an issue first helps align early.

## Development

### First Principles: Under the Hood

At its core, this tool manipulates the namespace pointers within process' [`struct task_struct`](https://elixir.bootlin.com/linux/v7.0.11/source/include/linux/sched.h#L820) 
in the Linux kernel. Each pointer within `struct task_struct`: `ns_proxy`, `fs`, `cred`, 
`sched_task_group`, etc, determines what the process _sees_ when it interacts w/ 
kernel-managed resources.

Every in-kernel resolver - VFS path walker, PID lookup, socket/route resolution, IPC table scan, 
credential check, etc,  dereferences its respective `*_ns` pointer from `current->nsproxy`. 
By reassigning these pointers, we give target process its own view of:

- **Mount table** (`CLONE_NEWNS`): controls FS topology
- **PID space** (`CLONE_NEWPID`): remaps process identifiers
- **Network stack** (`CLONE_NEWNET`): isolates net-interfaces, routes, and sokets
- **UID/GID Mapping** (`CLONE_NEWUSER`): remap credentials w/o real privileges
- **IPC objects** (`CLONE_NEWIPC`): separates SysV/POSIX IPC namespaces
- **UTS identifiers** (`CLONE_NEWUTS`): per-ns hostname and domainname

### Prerequisites

- [Rust toolchain](https://rustup.rs)

### Quick Start

```sh
git clone https://github.com/ritvikos/enclosure.git
cd enclosure
cargo build
```

### Run

```
cargo run -- \
  --unshare-user \
  --unshare-pid \
  --bind "/usr /usr" \
  --symlink "usr/bin /bin" \
  --symlink "usr/lib64 /lib64" \
  --symlink "usr/lib /lib" \
  --proc /proc \
  --dev /dev \
  --dir /tmp \
  -- /bin/sh
```

> **Note:** Symlinks aren't resolved automatically yet, pass explicitly via `--symlink`.
