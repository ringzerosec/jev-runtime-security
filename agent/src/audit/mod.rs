// SPDX-License-Identifier: Apache-2.0
// audit/mod.rs — Immutable, cryptographically chained audit log
//
// Every security event, policy decision, and configuration change is recorded
// as an AuditEntry. Entries are hash-chained (SHA-256) so any tampering is
// detectable via verify_chain().

pub mod log;

pub use log::{AuditEntryType, AuditLog};
