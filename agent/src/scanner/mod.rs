// SPDX-License-Identifier: Apache-2.0
// scanner — entropy + secret detection + supply chain scanning
// Heuristic patterns cover injection detection,
// entropy + secret detector covers supply chain risk.

pub mod baseline;
pub mod entropy;
pub mod jev_layer;
pub mod model_armor;
pub mod osv;
pub mod patterns;
pub mod skill_surface;
pub mod supply_chain;
pub mod verified_registry;
pub mod watcher;
