//! Sentinel kernel-side probes.
//!
//! Module layout mirrors `docs/architecture.md`:
//!
//! * [`syscalls`] — execve, openat, connect, ptrace, mount, setns
//! * [`container`] — unshare, capset, pivot_root (cgroup/ns escape signals)
//! * [`network`] — tcp_connect/accept/DNS (Phase 2, CO-RE)
//! * [`util`] — shared maps and event emitters
#![no_std]
#![no_main]

mod container;
mod network;
mod syscalls;
mod util;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
