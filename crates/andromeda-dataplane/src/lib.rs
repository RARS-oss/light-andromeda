//! # andromeda-dataplane
//!
//! The per-packet forwarding core. [`pipeline`] holds the socket-agnostic
//! forwarding logic (encap/decap/NAT) and is unit-tested over in-memory buffers.
//! [`afxdp`] (feature `afxdp`, Linux + libxdp) binds a real AF_XDP socket and
//! drives the pipeline from the RX ring — the actual kernel-bypass datapath.

pub mod pipeline;

#[cfg(feature = "afxdp")]
pub mod afxdp;

/// Unix-socket control plane for hot-reloading the fabric map (Linux/Unix only).
#[cfg(unix)]
pub mod control;

pub use pipeline::{Decision, FrameSlot, Pipeline, PipelineConfig};
