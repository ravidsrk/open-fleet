//! Native Rust verification & orchestration toolchain (`diff_scope`, `quarantine_check`,
//! `dispatch-sign`, `inventory`, `proof_status`, `chain_check`, `preflight`, `sessions`,
//! `solo_review`, `ci_check`, `readiness`, `run_report`, `verify`), pinned byte-for-byte
//! against the repository's adversarial test suites.

pub mod base64_codec;
pub mod chain_check;
pub mod ci_check;
pub mod diff_scope;
pub mod dispatch_sign;
pub mod inventory;
pub mod preflight;
pub mod proof_status;
pub mod quarantine;
pub mod readiness;
pub mod run_report;
pub mod sessions;
pub mod solo_review;
pub mod verify;
