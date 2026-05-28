//! `openat` kprobe — captures file opens for the harness cgroup. PRD §9.2.1.
//!
//! Maps to the `SyscallOpenat { path, flags, pid }` schema. The kernel-side probe reads the
//! `openat2`/`openat` syscall arguments, applies the cgroup filter (`cgroup_filter::is_allowed`),
//! and emits a fixed-layout record onto the shared perf array for the userspace loader to forward.
//!
//! Phase 3 scaffold (Linux/CI). The real eBPF program below is sketched as comments so this file
//! stays valid, buildable Rust; the kernel handler is `#![no_std]` Aya code compiled to BPF bytecode.

// Userspace side — attach the probe to the loaded object:
//
//   use aya::{Ebpf, programs::KProbe};
//
//   pub fn attach(bpf: &mut Ebpf) -> anyhow::Result<()> {
//       let program: &mut KProbe = bpf.program_mut("openat_probe").unwrap().try_into()?;
//       program.load()?;
//       program.attach("do_sys_openat2", 0)?;   // fall back to "do_sys_open" on older kernels
//       Ok(())
//   }
//
// Kernel side (separate bpf crate, #![no_std]) — fixed-layout record:
//
//   #[repr(C)]
//   pub struct OpenatEvent { pub pid: u32, pub flags: i32, pub path: [u8; 256] }
//
//   #[kprobe]
//   pub fn openat_probe(ctx: ProbeContext) -> u32 {
//       if !crate::cgroup_filter::is_allowed(bpf_get_current_cgroup_id()) { return 0; }
//       // read filename ptr (arg1) + flags (arg2); bpf_probe_read_user_str into path[..];
//       // EVENTS.output(&ctx, &event, 0);
//       0
//   }

/// Record layout the userspace reader decodes for each `openat` (mirrors the kernel `#[repr(C)]`).
/// Kept as a doc anchor for the Python decoder; real struct lives in the bpf crate on Linux.
pub const PATH_MAX_CAPTURE: usize = 256;
