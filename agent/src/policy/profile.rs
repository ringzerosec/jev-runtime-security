// SPDX-License-Identifier: Apache-2.0
// policy/profile.rs — Layered policy evaluator (4-layer override chain)
//
// Policy evaluation layers (lowest to highest priority):
//   1. Built-in defaults (from observer.rs profiles)
//   2. SPIFFE-bound rules (future — stub only)
//   3. User-defined rules (sled-persisted CRUD)
//   4. Learned baseline rules (from baseline.rs anomaly detection)
//
// Higher-numbered layers override lower ones per ActivityClass.
// Every evaluation returns a full trace for audit.

use serde::{Deserialize, Serialize};

use crate::analyzer::observer::{
    default_profile_for, ActivityClass, ActivityRule, AgentProfile, BaselineAction,
};

// ── Policy layer enum ─────────────────────────────────────────────────────────

/// Policy evaluation layers (lowest to highest priority).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PolicyLayer {
    BuiltIn,     // Layer 1: default profiles from observer.rs
    SpiffeBound, // Layer 2: per-SPIFFE-ID rules (future)
    UserRule,    // Layer 3: user-defined rules
    Learned,     // Layer 4: learned from baseline anomaly detection
}

impl PolicyLayer {
    /// Numeric priority — higher wins in override chain.
    pub fn priority(&self) -> u8 {
        match self {
            PolicyLayer::BuiltIn => 1,
            PolicyLayer::SpiffeBound => 2,
            PolicyLayer::UserRule => 3,
            PolicyLayer::Learned => 4,
        }
    }
}

// ── Layered rule ──────────────────────────────────────────────────────────────

/// A policy rule with its source layer for trace/audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayeredRule {
    pub rule: ActivityRule,
    pub layer: PolicyLayer,
    pub rule_id: String,
    pub source: String,
}

// ── Policy decision ───────────────────────────────────────────────────────────

/// Result of evaluating a policy — includes which layer won.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub activity: ActivityClass,
    pub action: BaselineAction,
    pub winning_layer: PolicyLayer,
    pub winning_rule_id: String,
    pub source: String,
    pub all_layers: Vec<LayeredRule>,
}

// ── Layered policy engine ─────────────────────────────────────────────────────

/// The layered policy evaluator.
///
/// This engine does NOT own state — it receives rules from each layer as
/// parameters and evaluates them. State is owned by the caller (observer.rs
/// for built-in, UserRuleStore for user rules, BaselineEngine for learned).
pub struct LayeredPolicyEngine;

impl LayeredPolicyEngine {
    pub fn new() -> Self {
        LayeredPolicyEngine
    }

    /// Evaluate all 4 layers for a given activity class.
    ///
    /// The highest-numbered layer that has a matching rule wins.
    /// Returns the winning action plus a full trace of all layers for audit.
    pub fn evaluate(
        &self,
        activity: &ActivityClass,
        agent_type: &str,
        _session_id: &str,
        user_rules: &[LayeredRule],
        learned_rules: &[LayeredRule],
    ) -> PolicyDecision {
        // Layer 1: built-in defaults from observer.rs profiles
        let profile = default_profile_for(agent_type);
        let built_in_rules = Self::profile_to_layered(&profile);

        // Layer 2: SPIFFE-bound rules (stub — empty for now)
        let spiffe_rules: Vec<LayeredRule> = Vec::new();

        // Merge all layers
        let all = Self::merge_rules(&built_in_rules, &spiffe_rules, user_rules, learned_rules);

        // Collect all rules matching this activity
        let mut matching: Vec<&LayeredRule> =
            all.iter().filter(|lr| lr.rule.class == *activity).collect();

        // Sort by layer priority (ascending) — last element = highest priority
        matching.sort_by_key(|lr| lr.layer.priority());

        if let Some(winner) = matching.last() {
            PolicyDecision {
                activity: activity.clone(),
                action: winner.rule.action.clone(),
                winning_layer: winner.layer.clone(),
                winning_rule_id: winner.rule_id.clone(),
                source: winner.source.clone(),
                all_layers: matching.iter().map(|lr| (*lr).clone()).collect(),
            }
        } else {
            // No rule found — default to Warn (conservative)
            PolicyDecision {
                activity: activity.clone(),
                action: BaselineAction::Warn,
                winning_layer: PolicyLayer::BuiltIn,
                winning_rule_id: "fallback".to_string(),
                source: "no_rule_found".to_string(),
                all_layers: Vec::new(),
            }
        }
    }

    /// Merge all layers into a single Vec, preserving layer annotations.
    /// The caller uses layer priority to determine which rule wins per ActivityClass.
    pub fn merge_rules(
        built_in: &[LayeredRule],
        spiffe: &[LayeredRule],
        user_rules: &[LayeredRule],
        learned_rules: &[LayeredRule],
    ) -> Vec<LayeredRule> {
        let mut all = Vec::with_capacity(
            built_in.len() + spiffe.len() + user_rules.len() + learned_rules.len(),
        );
        all.extend_from_slice(built_in);
        all.extend_from_slice(spiffe);
        all.extend_from_slice(user_rules);
        all.extend_from_slice(learned_rules);
        all
    }

    /// Convert an AgentProfile's rules into LayeredRules at the BuiltIn layer.
    fn profile_to_layered(profile: &AgentProfile) -> Vec<LayeredRule> {
        profile
            .rules
            .iter()
            .enumerate()
            .map(|(i, rule)| LayeredRule {
                rule: rule.clone(),
                layer: PolicyLayer::BuiltIn,
                rule_id: format!("builtin_{}_{}", profile.agent_type, i),
                source: format!("{}_profile", profile.agent_type),
            })
            .collect()
    }
}

impl Default for LayeredPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::observer::{ActivityClass, ActivityRule, BaselineAction};

    fn make_user_rule(activity: ActivityClass, action: BaselineAction) -> LayeredRule {
        LayeredRule {
            rule: ActivityRule {
                class: activity,
                action,
                description: "user-defined rule".to_string(),
            },
            layer: PolicyLayer::UserRule,
            rule_id: "user_1".to_string(),
            source: "user:manual".to_string(),
        }
    }

    fn make_learned_rule(activity: ActivityClass, action: BaselineAction) -> LayeredRule {
        LayeredRule {
            rule: ActivityRule {
                class: activity,
                action,
                description: "learned rule".to_string(),
            },
            layer: PolicyLayer::Learned,
            rule_id: "learned_1".to_string(),
            source: "learned:baseline".to_string(),
        }
    }

    #[test]
    fn test_layer_override() {
        // Layer 3 user rule overrides Layer 1 built-in
        let engine = LayeredPolicyEngine::new();

        // Built-in for claude: CredentialAccess = Block
        // User rule: CredentialAccess = Warn (override)
        let user_rules = vec![make_user_rule(
            ActivityClass::CredentialAccess,
            BaselineAction::Warn,
        )];

        let decision = engine.evaluate(
            &ActivityClass::CredentialAccess,
            "claude",
            "sess-1",
            &user_rules,
            &[],
        );

        assert_eq!(decision.action, BaselineAction::Warn);
        assert_eq!(decision.winning_layer, PolicyLayer::UserRule);
        assert_eq!(decision.winning_rule_id, "user_1");
    }

    #[test]
    fn test_built_in_default() {
        // With no overrides, built-in wins
        let engine = LayeredPolicyEngine::new();

        let decision = engine.evaluate(
            &ActivityClass::CredentialAccess,
            "claude",
            "sess-1",
            &[],
            &[],
        );

        assert_eq!(decision.action, BaselineAction::Block);
        assert_eq!(decision.winning_layer, PolicyLayer::BuiltIn);
    }

    #[test]
    fn test_policy_trace() {
        // Decision includes all layers in trace
        let engine = LayeredPolicyEngine::new();

        let user_rules = vec![make_user_rule(
            ActivityClass::FileRead,
            BaselineAction::Warn,
        )];
        let learned_rules = vec![make_learned_rule(
            ActivityClass::FileRead,
            BaselineAction::Allow,
        )];

        let decision = engine.evaluate(
            &ActivityClass::FileRead,
            "claude",
            "sess-1",
            &user_rules,
            &learned_rules,
        );

        // Learned (Layer 4) should win over User (Layer 3) and BuiltIn (Layer 1)
        assert_eq!(decision.winning_layer, PolicyLayer::Learned);
        assert_eq!(decision.action, BaselineAction::Allow);

        // Trace should include all 3 layers that had a FileRead rule
        assert!(
            decision.all_layers.len() >= 3,
            "Expected at least 3 layers in trace, got {}",
            decision.all_layers.len()
        );

        let layer_types: Vec<&PolicyLayer> =
            decision.all_layers.iter().map(|lr| &lr.layer).collect();
        assert!(layer_types.contains(&&PolicyLayer::BuiltIn));
        assert!(layer_types.contains(&&PolicyLayer::UserRule));
        assert!(layer_types.contains(&&PolicyLayer::Learned));
    }

    #[test]
    fn test_learned_rules_default_audit() {
        // Learned rules start as AUDIT (Warn action)
        let engine = LayeredPolicyEngine::new();

        let learned_rules = vec![make_learned_rule(
            ActivityClass::ProcessExec,
            BaselineAction::Warn, // AUDIT maps to Warn
        )];

        let decision = engine.evaluate(
            &ActivityClass::ProcessExec,
            "claude",
            "sess-1",
            &[],
            &learned_rules,
        );

        // Learned layer should win (Layer 4 > Layer 1)
        assert_eq!(decision.winning_layer, PolicyLayer::Learned);
        assert_eq!(decision.action, BaselineAction::Warn);
    }
}
