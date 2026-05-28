//! AI Auditor — Linux involuntary-telemetry eBPF loader (userspace side). PRD §9.2.1.
//!
//! Phase 3 scaffold. This binary is the Aya **userspace loader**: it opens the compiled eBPF object,
//! attaches the kprobes/tracepoints in `probes/`, programs the cgroup allowlist (`cgroup_filter`),
//! and pumps the perf buffer, forwarding decoded records to the Python reader
//! (`auditor/involuntary/linux.py`) which normalizes them into the `Syscall*` schemas.
//!
//! IMPORTANT: this compiles and runs on **Linux only** (verified in Phase 3 / CI). It is intentionally
//! comment-level scaffolding — the real Aya wiring is sketched in the modules below but not yet built
//! out, so this file stays as a valid no-op `main` that compiles on any target.
//!
//! Capabilities required at runtime (PRD §9.2.1): CAP_BPF, CAP_PERFMON, CAP_SYS_RESOURCE (memlock);
//! CAP_SYS_ADMIN on kernels older than 5.8.
//!
//! Module layout (built out on Linux): `cgroup_filter.rs` programs the per-run cgroup allowlist;
//! `probes/{openat,connect,execve,sendto}.rs` each own one kprobe/tracepoint and its `attach()` +
//! kernel-side handler. They are declared here (`#[path]`) once the Aya build is wired up:
//!
//!   #[path = "cgroup_filter.rs"] mod cgroup_filter;
//!   #[path = "probes/openat.rs"]  mod openat;
//!   #[path = "probes/connect.rs"] mod connect;
//!   #[path = "probes/execve.rs"]  mod execve;
//!   #[path = "probes/sendto.rs"]  mod sendto;

// Real implementation (Linux) — sketch:
//
//   use aya::{Ebpf, programs::KProbe};
//   use aya::maps::{HashMap, perf::AsyncPerfEventArray};
//   use aya::util::online_cpus;
//   use bytes::BytesMut;
//
//   #[tokio::main]
//   async fn main() -> anyhow::Result<()> {
//       // 1. Load the compiled eBPF object (built by the bpf-linker target).
//       let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/auditor-ebpf")))?;
//
//       // 2. Attach the syscall probes (see probes/{openat,connect,execve,sendto}.rs).
//       probes::openat::attach(&mut bpf)?;
//       probes::connect::attach(&mut bpf)?;
//       probes::execve::attach(&mut bpf)?;
//       probes::sendto::attach(&mut bpf)?;
//
//       // 3. Scope to the harness cgroup: write its cgroup id into the in-kernel allowlist map so the
//       //    probes drop events from every other process (one cgroup per run — see cgroup_filter.rs).
//       let mut allow: HashMap<_, u64, u8> = HashMap::try_from(bpf.map_mut("CGROUP_ALLOWLIST")?)?;
//       cgroup_filter::allow_run_cgroup(&mut allow, /* cgroup_id from CLI/env */ 0)?;
//
//       // 4. Pump the perf buffer on every online CPU; forward each fixed-layout record to the
//       //    Python reader over the established channel (stdout pipe / shared ring).
//       let mut events = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
//       for cpu_id in online_cpus()? {
//           let mut buf = events.open(cpu_id, None)?;
//           tokio::spawn(async move {
//               let mut buffers = vec![BytesMut::with_capacity(1024); 16];
//               loop {
//                   let events = buf.read_events(&mut buffers).await.unwrap();
//                   for b in buffers.iter().take(events.read) {
//                       // decode the #[repr(C)] record header + payload; emit to the reader.
//                   }
//               }
//           });
//       }
//
//       // 5. Run until signalled; on shutdown the maps/links drop and the probes detach.
//       tokio::signal::ctrl_c().await?;
//       Ok(())
//   }

/// Phase 3 scaffold entry point — compiles to a no-op until the Aya wiring above is built on Linux.
fn main() {
    // TODO(phase3, Linux/CI): replace with the #[tokio::main] loader sketched above.
}
