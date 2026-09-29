//! Sentinel agent library: decode → enrich → features → rules → sinks.
//!
//! `main.rs` wires these modules together; everything here is unit-testable
//! without loading eBPF (see `cargo test -p sentinel`).

pub mod enrich;
pub mod event;
pub mod features;
pub mod ingest;
pub mod loader;
pub mod ml;
pub mod rules;
pub mod sink;
