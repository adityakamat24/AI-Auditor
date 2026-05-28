//! `sendto` / `sendmsg` kprobe — captures datagram sends for the harness cgroup. PRD §9.2.1.
//!
//! Maps to the `SyscallSendto { fd, bytes_sent, dest_addr, pid }` schema. Hooks `__sys_sendto`
//! (and `__sys_sendmsg`), reads the file descriptor, byte count, and destination sockaddr when one
//! is supplied (connected sockets pass NULL — `dest_addr` is then absent), and emits a record after
//! the cgroup filter passes. This probe is rate-limited in-kernel to avoid flooding (PRD §9.2.1).
//!
//! Phase 3 scaffold (Linux/CI). The Aya wiring below is comment-level so this file stays valid Rust.

// Userspace side:
//
//   use aya::{Ebpf, programs::KProbe};
//
//   pub fn attach(bpf: &mut Ebpf) -> anyhow::Result<()> {
//       let program: &mut KProbe = bpf.program_mut("sendto_probe").unwrap().try_into()?;
//       program.load()?;
//       program.attach("__sys_sendto", 0)?;
//       Ok(())
//   }
//
// Kernel side (#![no_std]) — fixed-layout record (has_dest flags whether dest_addr is valid):
//
//   #[repr(C)]
//   pub struct SendtoEvent { pub pid: u32, pub fd: i32, pub bytes_sent: u64, pub has_dest: u8, pub dest_addr: [u8; 16] }
//
//   #[kprobe]
//   pub fn sendto_probe(ctx: ProbeContext) -> u32 {
//       if !crate::cgroup_filter::is_allowed(bpf_get_current_cgroup_id()) { return 0; }
//       // token-bucket rate-limit per cgroup; read fd (arg0), len (arg2), dest sockaddr (arg4) if non-NULL;
//       // EVENTS.output(&ctx, &event, 0);
//       0
//   }

/// Length of the optional destination-address buffer carried per sendto record.
pub const DEST_ADDR_LEN: usize = 16;
