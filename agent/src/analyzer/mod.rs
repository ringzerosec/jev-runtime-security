// SPDX-License-Identifier: Apache-2.0
// analyzer — behavioral timeline + anomaly detection + provenance graph.
// Event history stored in sled (embedded key-value store).

pub mod aggregator;
pub mod baseline;
pub mod correlation;
pub mod dataset;
pub mod edge;
pub mod graph;
pub mod heuristics;
pub mod intent_diff;
pub mod observer;
pub mod rule_compiler;
pub mod slm;
pub mod timeline;
pub mod tool_call;
