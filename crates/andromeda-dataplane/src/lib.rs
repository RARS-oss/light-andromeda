//! # andromeda-dataplane
//!
//! The per-packet forwarding core that will run inside the AF_XDP receive loop.
//!
//! The AF_XDP socket plumbing (UMEM, FILL/COMPLETION/RX/TX rings) lands in the
//! next iteration. This module already hosts the *pipeline logic* that is
//! independent of the socket layer, so it can be unit-tested against in-memory
//! buffers and then dropped straight onto the ring loop.

pub mod pipeline;

pub use pipeline::{Decision, Pipeline, PipelineConfig};
