// SPDX-License-Identifier: Apache-2.0
// Wire protocol — JSON over Unix socket (newline-delimited)

use super::event::SecurityEvent;
use super::policy::{EnforceMode, NetworkMode};
use serde::{Deserialize, Serialize};

/// Messages sent from driver → daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DriverMessage {
    Event {
        event_type: u32,
        pid: u32,
        uid: u32,
        comm: String,
        path: Option<String>,
        remote_ip: Option<String>,
        remote_port: Option<u16>,
        blocked: u32,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        args: Option<String>,
    },
}

/// Messages sent from UI/CLI → daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientRequest {
    Subscribe,
    GetStatus,
    GetEvents {
        limit: Option<usize>,
    },
    ScanSkill {
        path: String,
    },
    UpdatePolicy {
        action: String,
        value: Option<serde_json::Value>,
    },
    SetNetworkMode {
        mode: NetworkMode,
    },
    GetNetworkMode,
    SetEnforceMode {
        mode: EnforceMode,
    },
    AddKeyRoute {
        key_name: String,
        key_value: String,
        destination: String,
    },
    RemoveKeyRoute {
        key_name: String,
    },
    AddComment,
    RecordIntent {
        record: serde_json::Value,
    },
    ScanSkillsAuto,
}

/// Messages sent from daemon → UI/CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonMessage {
    Subscribed,
    Event { payload: SecurityEvent },
    Threat { payload: serde_json::Value },
    Status { payload: serde_json::Value },
    Events { payload: Vec<SecurityEvent> },
    NetworkMode { mode: NetworkMode },
    SkillScan { payload: serde_json::Value },
    Ok,
    Error { message: String },
}
