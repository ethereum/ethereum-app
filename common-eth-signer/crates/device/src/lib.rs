//! Device orchestration: wires decoding, signing, and the confirmation UI into
//! the end-to-end signing flow, plus the host test-scenario entry point.

mod flow;
mod rng;
mod scenario;

pub use flow::run_signing_flow;
pub use scenario::run_scenario;
