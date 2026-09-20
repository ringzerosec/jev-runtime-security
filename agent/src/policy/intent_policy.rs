// SPDX-License-Identifier: Apache-2.0
// policy/intent_policy.rs — Intent-aware policy layer
//
// Classifies tool call intents into business categories and evaluates
// configurable Block / Escalate / Allow / Audit rules per category.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ── Business categories ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BusinessCategory {
    Pii,
    Credentials,
    CustomerData,
    Financial,
    Health,
    Legal,
    SourceCode,
    Config,
    Public,
    Unknown,
}

impl std::fmt::Display for BusinessCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            BusinessCategory::Pii => "pii",
            BusinessCategory::Credentials => "credentials",
            BusinessCategory::CustomerData => "customer_data",
            BusinessCategory::Financial => "financial",
            BusinessCategory::Health => "health",
            BusinessCategory::Legal => "legal",
            BusinessCategory::SourceCode => "source_code",
            BusinessCategory::Config => "config",
            BusinessCategory::Public => "public",
            BusinessCategory::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

// ── Policy actions ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntentAction {
    Allow,
    Audit,
    Escalate,
    Block,
}

// ── Rule ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentRule {
    pub category: BusinessCategory,
    pub action: IntentAction,
    pub description: String,
}

// ── Classification result ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyResult {
    pub intent: String,
    pub category: BusinessCategory,
    pub action: IntentAction,
    pub rule: Option<String>,
}

// ── Policy engine ─────────────────────────────────────────────────────────────

pub struct IntentAwarePolicy {
    rules: RwLock<HashMap<BusinessCategory, IntentRule>>,
}

impl IntentAwarePolicy {
    /// Build with secure defaults:
    /// - credentials, pii, financial, health, legal → Block
    /// - customer_data, config → Escalate
    /// - source_code → Audit
    /// - public, unknown → Allow
    pub fn new() -> Arc<Self> {
        let mut rules = HashMap::new();

        let defaults: &[(BusinessCategory, IntentAction, &str)] = &[
            (
                BusinessCategory::Credentials,
                IntentAction::Block,
                "Block all credential access by default",
            ),
            (
                BusinessCategory::Pii,
                IntentAction::Block,
                "Block PII access — GDPR/privacy compliance",
            ),
            (
                BusinessCategory::Financial,
                IntentAction::Block,
                "Block financial data access — SOX/PCI compliance",
            ),
            (
                BusinessCategory::Health,
                IntentAction::Block,
                "Block health data access — HIPAA compliance",
            ),
            (
                BusinessCategory::Legal,
                IntentAction::Escalate,
                "Escalate legal document access for human review",
            ),
            (
                BusinessCategory::CustomerData,
                IntentAction::Escalate,
                "Escalate customer data access for review",
            ),
            (
                BusinessCategory::Config,
                IntentAction::Escalate,
                "Escalate config changes for admin review",
            ),
            (
                BusinessCategory::SourceCode,
                IntentAction::Audit,
                "Audit source code access — no block",
            ),
            (
                BusinessCategory::Public,
                IntentAction::Allow,
                "Allow public data access",
            ),
            (
                BusinessCategory::Unknown,
                IntentAction::Allow,
                "Allow unknown categories by default",
            ),
        ];

        for (cat, action, desc) in defaults {
            rules.insert(
                cat.clone(),
                IntentRule {
                    category: cat.clone(),
                    action: action.clone(),
                    description: desc.to_string(),
                },
            );
        }

        Arc::new(Self {
            rules: RwLock::new(rules),
        })
    }

    /// Get all current rules.
    pub async fn rules(&self) -> Vec<IntentRule> {
        let r = self.rules.read().await;
        r.values().cloned().collect()
    }

    /// Upsert a rule.
    pub async fn set_rule(&self, rule: IntentRule) {
        let mut r = self.rules.write().await;
        r.insert(rule.category.clone(), rule);
    }

    /// Classify an intent string + optional path/args context into a business category
    /// and evaluate the applicable policy rule.
    pub async fn classify_and_evaluate(
        &self,
        intent: &str,
        context: Option<&str>,
    ) -> ClassifyResult {
        let category = classify_intent(intent, context);
        let rules = self.rules.read().await;
        let (action, rule_desc) = if let Some(rule) = rules.get(&category) {
            (rule.action.clone(), Some(rule.description.clone()))
        } else {
            (IntentAction::Allow, None)
        };
        ClassifyResult {
            intent: intent.to_string(),
            category,
            action,
            rule: rule_desc,
        }
    }
}

impl Default for IntentAwarePolicy {
    fn default() -> Self {
        // note: use Arc::new(IntentAwarePolicy::new()) in practice
        Self {
            rules: RwLock::new(HashMap::new()),
        }
    }
}

// ── Intent → category classifier ─────────────────────────────────────────────

/// Classify an intent string (and optional file path / argument context string)
/// into a `BusinessCategory`.  Pure function — no I/O.
pub fn classify_intent(intent: &str, context: Option<&str>) -> BusinessCategory {
    let i = intent.to_lowercase();
    let ctx = context.map(|s| s.to_lowercase()).unwrap_or_default();

    // ── credential signals ────────────────────────────────────────────────
    if i.contains("credential") || i.contains("credential_read") || i.contains("secret") {
        return BusinessCategory::Credentials;
    }
    if ctx.contains("password")
        || ctx.contains("passwd")
        || ctx.contains("token")
        || ctx.contains("api_key")
        || ctx.contains("private_key")
        || ctx.contains("id_rsa")
        || ctx.contains("id_ed25519")
        || ctx.contains(".aws/credentials")
        || ctx.contains(".ssh/")
        || ctx.contains("keychain")
        || ctx.contains("vault")
    {
        return BusinessCategory::Credentials;
    }

    // ── PII signals ───────────────────────────────────────────────────────
    if i.contains("pii") || i.contains("personal") || i.contains("gdpr") {
        return BusinessCategory::Pii;
    }
    if ctx.contains("ssn")
        || ctx.contains("social_security")
        || ctx.contains("date_of_birth")
        || ctx.contains("passport")
        || ctx.contains("driver_license")
        || ctx.contains("biometric")
    {
        return BusinessCategory::Pii;
    }

    // ── financial signals ─────────────────────────────────────────────────
    if i.contains("financial") || i.contains("payment") || i.contains("billing") {
        return BusinessCategory::Financial;
    }
    if ctx.contains("credit_card")
        || ctx.contains("bank_account")
        || ctx.contains("stripe")
        || ctx.contains("paypal")
        || ctx.contains("invoice")
        || ctx.contains("revenue")
    {
        return BusinessCategory::Financial;
    }

    // ── health signals ────────────────────────────────────────────────────
    if i.contains("health") || i.contains("medical") || i.contains("hipaa") {
        return BusinessCategory::Health;
    }
    if ctx.contains("patient")
        || ctx.contains("diagnosis")
        || ctx.contains("prescription")
        || ctx.contains("ehr")
        || ctx.contains("epic")
        || ctx.contains("fhir")
    {
        return BusinessCategory::Health;
    }

    // ── legal signals ─────────────────────────────────────────────────────
    if i.contains("legal") || i.contains("contract") || i.contains("compliance") {
        return BusinessCategory::Legal;
    }
    if ctx.contains(".pdf")
        && (ctx.contains("agreement")
            || ctx.contains("nda")
            || ctx.contains("contract")
            || ctx.contains("terms"))
    {
        return BusinessCategory::Legal;
    }

    // ── customer data signals ─────────────────────────────────────────────
    if i.contains("customer") || i.contains("user_data") || i.contains("crm") {
        return BusinessCategory::CustomerData;
    }
    if ctx.contains("salesforce")
        || ctx.contains("hubspot")
        || ctx.contains("customer_id")
        || ctx.contains("user_id")
    {
        return BusinessCategory::CustomerData;
    }

    // ── config signals ────────────────────────────────────────────────────
    if i.contains("config") || i.contains("settings") || i.contains("deploy") {
        return BusinessCategory::Config;
    }
    if ctx.contains(".toml")
        || ctx.contains(".yaml")
        || ctx.contains(".yml")
        || ctx.contains(".json")
        || ctx.contains(".env")
        || ctx.contains("docker")
        || ctx.contains("kubernetes")
        || ctx.contains("terraform")
    {
        return BusinessCategory::Config;
    }

    // ── source code signals ───────────────────────────────────────────────
    if i.contains("source_code")
        || i.contains("file_write")
        || i.contains("file_read")
        || i.contains("file_search")
        || i.contains("shell_execution")
        || i.contains("package_operation")
    {
        return BusinessCategory::SourceCode;
    }

    // ── public signals ────────────────────────────────────────────────────
    if i.contains("network_request") || i.contains("web_fetch") || i.contains("search") {
        return BusinessCategory::Public;
    }

    BusinessCategory::Unknown
}
