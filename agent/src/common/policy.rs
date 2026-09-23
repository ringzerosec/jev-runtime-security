// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// Only agent-origin traffic allowed
    Low,
    /// Agent + all child processes
    Medium,
    /// All outbound including browser, consent prompt per new destination
    High,
}

impl Default for NetworkMode {
    fn default() -> Self {
        Self::Low
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EnforceMode {
    /// Block policy violations
    Enforce,
    /// Log only, do not block
    Observe,
}

impl Default for EnforceMode {
    fn default() -> Self {
        Self::Enforce
    }
}
