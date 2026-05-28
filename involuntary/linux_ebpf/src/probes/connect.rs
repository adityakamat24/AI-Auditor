//! `connect` kprobe — captures outbound connection attempts for the harness cgroup. PRD §9.2.1.
//!
//! Maps to the `SyscallConnect { family, addr, port, pid }` schema. Hooks `__sys_connect` (and, for
//! richer destination data, `tcp_v4_connect` / `tcp_v6_connect`) to read the destination sockaddr,
//! derives `family` from `sa_family` (AF_INET / AF_INET6 / AF_UNIX), and emits a record after the
//! cgroup filter passes.
//!
//! Phase 3 scaffold (Linux/CI). The Aya wiring below is comment-level so this file stays valid Rust.

// Userspace side:
//
//   use aya::{Ebpf, programs::KProbe};
//
//   pub fn attach(bpf: &mut Ebpf) -> anyhow::Result<()> {
//       let program: &mut KProbe = bpf.program_mut("connect_probe").unwrap().try_into()?;
//       program.load()?;
//       program.attach("__sys_connect", 0)?;
//       Ok(())
//   }
//
// Kernel side (#![no_std]) — fixed-layout record (addr held as 16 bytes, IPv4-mapped for v4):
//
//   #[repr(C)]
//   pub struct ConnectEvent { pub pid: u32, pub family: u16, pub port: u16, pub addr: [u8; 16] }
//
//   #[kprobe]
//   pub fn connect_probe(ctx: ProbeContext) -> u32 {
//       if !crate::cgroup_filter::is_allowed(bpf_get_current_cgroup_id()) { return 0; }
//       // read sockaddr ptr (arg1); switch on sa_family for AF_INET/AF_INET6; copy addr+port (ntohs);
//       // EVENTS.output(&ctx, &event, 0);
//       0
//   }

/// Length of the address buffer carried per connect record (IPv6-sized; IPv4 is IPv4-mapped).
pub const ADDR_LEN: usize = 16;
