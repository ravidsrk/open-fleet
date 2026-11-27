//! Native Rust verification toolchain (`diff_scope`, `quarantine_check`,
//! `dispatch-sign`, `inventory`, `proof_status`), pinned byte-for-byte against
//! the repository's adversarial Python test suites.

pub mod base64_codec;
pub mod diff_scope;
pub mod dispatch_sign;
pub mod inventory;
pub mod proof_status;
pub mod quarantine;
