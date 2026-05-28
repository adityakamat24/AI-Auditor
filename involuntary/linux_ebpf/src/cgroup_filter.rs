//! Cgroup filter — scopes involuntary events to the harness run's cgroup. PRD §9.2.1.
//!
//! Each run gets its own cgroup; the loader writes that cgroup id into an in-kernel allowlist map so
//! every probe can cheaply drop events from unrelated processes. The kernel side calls
//! `is_allowed(bpf_get_current_cgroup_id())` as the first thing in each handler; the userspace side
//! programs the map via `allow_run_cgroup` / `forget_run_cgroup` as runs start and stop.
//!
//! Phase 3 scaffold (Linux/CI). The Aya wiring below is comment-level so this file stays valid Rust.

// Shared map (declared once, referenced by every probe):
//
//   use aya_ebpf::maps::HashMap;            // kernel side
//   #[map] static CGROUP_ALLOWLIST: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);
//
// Kernel side — the per-event check the handlers call first:
//
//   #[inline(always)]
//   pub fn is_allowed(cgroup_id: u64) -> bool {
//       unsafe { CGROUP_ALLOWLIST.get(&cgroup_id).is_some() }
//   }
//
// Userspace side — program / clear the allowlist as runs come and go:
//
//   use aya::maps::HashMap;
//
//   pub fn allow_run_cgroup(map: &mut HashMap<_, u64, u8>, cgroup_id: u64) -> anyhow::Result<()> {
//       map.insert(cgroup_id, 1, 0)?;   // one entry per active run
//       Ok(())
//   }
//
//   pub fn forget_run_cgroup(map: &mut HashMap<_, u64, u8>, cgroup_id: u64) -> anyhow::Result<()> {
//       map.remove(&cgroup_id)?;
//       Ok(())
//   }

/// Max concurrent harness cgroups the allowlist map holds (one per active run).
pub const MAX_TRACKED_CGROUPS: u32 = 256;
