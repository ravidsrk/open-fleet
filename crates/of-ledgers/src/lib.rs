//! Native cryptographic ledgers for open-fleet:
//! - `egress`: content-free, hash-chained off-repo send receipts (`runtime/scripts/egress.py`)
//! - `decisions`: durable governance ledger & Ed25519 human-grant tooling (`runtime/scripts/decisions.py`)

pub mod decisions_cli;
pub mod egress;
