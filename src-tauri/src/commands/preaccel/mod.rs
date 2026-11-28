//! Domestic pre-acceleration commands: control plane (`ctrl`) and live benchmarking (`bench`).

pub(in crate::commands) mod bench;
pub(in crate::commands) mod ctrl;

pub use bench::*;
pub use ctrl::*;
