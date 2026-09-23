// SPDX-License-Identifier: Apache-2.0
// policy/user_rules.rs — User-defined policy rules with sled persistence
//
// CRUD interface for user-created rules that feed into Layer 3 of the
// LayeredPolicyEngine. Rules are persisted to the "user_rules" sled tree
// and survive daemon restarts.
//
// Rules can be global (agent_type = None) or agent-specific.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sled::Db;

use crate::analyzer::observer::{ActivityClass, ActivityRule, BaselineAction};
use crate::policy::profile::{LayeredRule, PolicyLayer};

// ── Constants ─────────────────────────────────────────────────────────────────

const USER_RULES_TREE: &str = "user_rules";

// ── User rule ─────────────────────────────────────────────────────────────────

/// A user-created policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRule {
    pub id: String,
    pub agent_type: Option<String>, // None = applies to all agents
    pub activity: ActivityClass,
    pub action: BaselineAction,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
}

// ── sled serialization ────────────────────────────────────────────────────────

fn encode_rule(r: &UserRule) -> Vec<u8> {
    serde_json::to_vec(r).unwrap_or_default()
}

fn decode_rule(bytes: &[u8]) -> Option<UserRule> {
    serde_json::from_slice(bytes).ok()
}

// ── User rule store ───────────────────────────────────────────────────────────

/// Sled-backed user rule store.
pub struct UserRuleStore {
    db: Arc<Db>,
}

impl UserRuleStore {
    /// Open a user rule store backed by a sled DB.
    /// The store uses the "user_rules" tree within the provided DB.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Open a temporary in-memory store (for tests).
    pub fn new_temp() -> Self {
        let db = sled::Config::default()
            .temporary(true)
            .open()
            .expect("Failed to open temporary sled DB");
        Self { db: Arc::new(db) }
    }

    /// Get the sled tree for user rules.
    fn tree(&self) -> sled::Tree {
        self.db.open_tree(USER_RULES_TREE).expect("sled tree open")
    }

    /// Get a reference to the underlying sled DB (for sharing with other stores).
    pub fn db(&self) -> &Arc<Db> {
        &self.db
    }

    /// Create a new user rule. Persists to sled.
    pub fn create(&self, rule: UserRule) -> anyhow::Result<()> {
        let tree = self.tree();
        tree.insert(rule.id.as_bytes(), encode_rule(&rule))?;
        Ok(())
    }

    /// Get a user rule by ID.
    pub fn get(&self, id: &str) -> Option<UserRule> {
        let tree = self.tree();
        tree.get(id.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| decode_rule(&v))
    }

    /// List all user rules.
    pub fn list(&self) -> Vec<UserRule> {
        let tree = self.tree();
        tree.iter()
            .filter_map(|entry| entry.ok())
            .filter_map(|(_, v)| decode_rule(&v))
            .collect()
    }

    /// List rules matching a specific agent type (returns global + agent-specific rules).
    pub fn list_for_agent(&self, agent_type: &str) -> Vec<UserRule> {
        self.list()
            .into_iter()
            .filter(|r| {
                r.enabled && (r.agent_type.is_none() || r.agent_type.as_deref() == Some(agent_type))
            })
            .collect()
    }

    /// Update a user rule by ID. Returns true if the rule existed and was updated.
    pub fn update(&self, id: &str, rule: UserRule) -> bool {
        let tree = self.tree();
        if tree.get(id.as_bytes()).ok().flatten().is_some() {
            let _ = tree.insert(id.as_bytes(), encode_rule(&rule));
            true
        } else {
            false
        }
    }

    /// Delete a user rule by ID. Returns true if the rule existed and was deleted.
    pub fn delete(&self, id: &str) -> bool {
        let tree = self.tree();
        tree.remove(id.as_bytes()).ok().flatten().is_some()
    }

    /// Convert user rules for a given agent type into LayeredRules for the evaluator.
    pub fn to_layered_rules(&self, agent_type: &str) -> Vec<LayeredRule> {
        self.list_for_agent(agent_type)
            .into_iter()
            .map(|ur| LayeredRule {
                rule: ActivityRule {
                    class: ur.activity.clone(),
                    action: ur.action.clone(),
                    description: ur.description.clone(),
                },
                layer: PolicyLayer::UserRule,
                rule_id: ur.id.clone(),
                source: format!("user:{}", ur.agent_type.as_deref().unwrap_or("global")),
            })
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(id: &str, agent_type: Option<&str>, activity: ActivityClass) -> UserRule {
        UserRule {
            id: id.to_string(),
            agent_type: agent_type.map(|s| s.to_string()),
            activity,
            action: BaselineAction::Block,
            description: format!("test rule {}", id),
            created_at: Utc::now(),
            enabled: true,
        }
    }

    #[test]
    fn test_crud_roundtrip() {
        let store = UserRuleStore::new_temp();

        // Create
        let rule = make_rule("r1", None, ActivityClass::FileWrite);
        store.create(rule.clone()).unwrap();

        // Get
        let fetched = store.get("r1");
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.id, "r1");
        assert_eq!(fetched.activity, ActivityClass::FileWrite);

        // List
        let all = store.list();
        assert_eq!(all.len(), 1);

        // Update
        let mut updated = fetched.clone();
        updated.action = BaselineAction::Warn;
        updated.description = "updated rule".to_string();
        assert!(store.update("r1", updated));

        let fetched2 = store.get("r1").unwrap();
        assert_eq!(fetched2.action, BaselineAction::Warn);
        assert_eq!(fetched2.description, "updated rule");

        // Delete
        assert!(store.delete("r1"));
        assert!(store.get("r1").is_none());
        assert_eq!(store.list().len(), 0);

        // Delete non-existent returns false
        assert!(!store.delete("r1"));
    }

    #[test]
    fn test_agent_filter() {
        let store = UserRuleStore::new_temp();

        // Global rule (applies to all agents)
        let global = make_rule("g1", None, ActivityClass::CredentialAccess);
        store.create(global).unwrap();

        // Agent-specific rule for claude
        let claude_rule = make_rule("c1", Some("claude"), ActivityClass::ProcessExec);
        store.create(claude_rule).unwrap();

        // Agent-specific rule for chatgpt
        let chatgpt_rule = make_rule("gpt1", Some("chatgpt"), ActivityClass::NetworkConnect);
        store.create(chatgpt_rule).unwrap();

        // list_for_agent("claude") should return global + claude-specific
        let claude_rules = store.list_for_agent("claude");
        assert_eq!(claude_rules.len(), 2);
        let ids: Vec<&str> = claude_rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"g1"));
        assert!(ids.contains(&"c1"));
        assert!(!ids.contains(&"gpt1"));

        // list_for_agent("chatgpt") should return global + chatgpt-specific
        let chatgpt_rules = store.list_for_agent("chatgpt");
        assert_eq!(chatgpt_rules.len(), 2);
        let ids: Vec<&str> = chatgpt_rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"g1"));
        assert!(ids.contains(&"gpt1"));

        // list_for_agent("unknown") should return only global
        let unknown_rules = store.list_for_agent("unknown");
        assert_eq!(unknown_rules.len(), 1);
        assert_eq!(unknown_rules[0].id, "g1");
    }

    #[test]
    fn test_sled_persistence() {
        // Rules survive store recreation (same sled DB)
        let db = sled::Config::default()
            .temporary(true)
            .open()
            .expect("sled open");
        let db = Arc::new(db);

        // Create store #1 and insert a rule
        {
            let store = UserRuleStore::new(db.clone());
            let rule = make_rule("persist1", None, ActivityClass::FileDelete);
            store.create(rule).unwrap();
        }

        // Create store #2 from the same DB — rule should still be there
        {
            let store = UserRuleStore::new(db.clone());
            let fetched = store.get("persist1");
            assert!(fetched.is_some(), "Rule should survive store recreation");
            assert_eq!(fetched.unwrap().activity, ActivityClass::FileDelete);
        }
    }

    #[test]
    fn test_to_layered_rules() {
        let store = UserRuleStore::new_temp();

        let rule = make_rule("lr1", Some("claude"), ActivityClass::NetworkConnect);
        store.create(rule).unwrap();

        let layered = store.to_layered_rules("claude");
        assert_eq!(layered.len(), 1);
        assert_eq!(layered[0].layer, PolicyLayer::UserRule);
        assert_eq!(layered[0].rule_id, "lr1");
        assert_eq!(layered[0].source, "user:claude");
    }

    #[test]
    fn test_disabled_rules_excluded() {
        let store = UserRuleStore::new_temp();

        let mut rule = make_rule("d1", None, ActivityClass::FileRead);
        rule.enabled = false;
        store.create(rule).unwrap();

        // Disabled rules should not appear in list_for_agent
        let rules = store.list_for_agent("claude");
        assert!(rules.is_empty());

        // But should still appear in list() (all rules)
        let all = store.list();
        assert_eq!(all.len(), 1);
    }
}
