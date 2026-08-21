//! # andromeda-dataplane
//!
//! The per-packet forwarding core. [`pipeline`] holds the socket-agnostic
//! forwarding logic (encap/decap/NAT) and is unit-tested over in-memory buffers.
//! [`afxdp`] (feature `afxdp`, Linux + libxdp) binds a real AF_XDP socket and
//! drives the pipeline from the RX ring — the actual kernel-bypass datapath.

pub mod pipeline;

#[cfg(feature = "afxdp")]
pub mod afxdp;

pub use pipeline::{Decision, Pipeline, PipelineConfig};
