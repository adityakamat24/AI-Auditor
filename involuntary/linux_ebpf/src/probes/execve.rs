//! `execve` tracepoint — captures process executions for the harness cgroup. PRD §9.2.1.
//!
//! Maps to the `SyscallExecve { binary, argv, pid }` schema. Attaches to the
//! `syscalls:sys_enter_execve` tracepoint, reads the program path and the first 16 argv entries
//! (each truncated to 256 bytes per PRD §9.2.1), and emits a record after the cgroup filter passes.
//!
//! Phase 3 scaffold (Linux/CI). The Aya wiring below is comment-level so this file stays valid Rust.

// Userspace side:
//
//   use aya::{Ebpf, programs::TracePoint};
//
//   pub fn attach(bpf: &mut Ebpf) -> anyhow::Result<()> {
//       let program: &mut TracePoint = bpf.program_mut("execve_probe").unwrap().try_into()?;
//       program.load()?;
//       program.attach("syscalls", "sys_enter_execve")?;
//       Ok(())
//   }
//
// Kernel side (#![no_std]) — fixed-layout record (argv flattened, NUL-separated):
//
//   #[repr(C)]
//   pub struct ExecveEvent { pub pid: u32, pub argc: u16, pub binary: [u8; 256], pub argv: [u8; 16 * 256] }
//
//   #[tracepoint]
//   pub fn execve_probe(ctx: TracePointContext) -> u32 {
//       if !crate::cgroup_filter::is_allowed(bpf_get_current_cgroup_id()) { return 0; }
//       // read filename + argv[..16] via bpf_probe_read_user_str (each capped to ARG_MAX_CAPTURE);
//       // EVENTS.output(&ctx, &event, 0);
//       0
//   }

/// Per-PRD argv capture limits: first `ARGV_MAX` args, each truncated to `ARG_MAX_CAPTURE` bytes.
pub const ARGV_MAX: usize = 16;
pub const ARG_MAX_CAPTURE: usize = 256;
