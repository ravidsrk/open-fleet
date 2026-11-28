//! Native cryptographic and telemetry ledgers for open-fleet:
//! - `egress`: content-free, hash-chained off-repo send receipts (`runtime/scripts/egress.py`)
//! - `decisions`: durable governance ledger & Ed25519 human-grant tooling (`runtime/scripts/decisions.py`)
//! - `events`: append-only run-event ledger, WIP-curve derivation & report checks (`runtime/scripts/events.py`)

pub mod decisions_cli;
pub mod egress;
pub mod events;
