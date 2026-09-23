// SPDX-License-Identifier: Apache-2.0
//
// review.rs — the review queue.
//
// Every kernel denial and every check flag lands here with its trace attached,
// and a human sets one label on it: benign, real-threat, or false-positive.
//
// There is no model in this file, and that is the point. We have no labelled
// denials yet, so there is nothing honest to train on. This queue is the thing
// that collects them: each labelled item is one training row for the triage and
// correlation models described in models/README.md, which are NOT in this
// release. Ship the collector first.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// What put this item in the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The kernel refused an action.
    KernelDeny,
    /// A check scored an agent action as something other than benign.
    CheckFlag,
    /// A policy-mutating API call was refused because its caller could not be
    /// shown to be a human operator — an agent process, or one that could not
    /// be identified at all.
    PolicyMutationRefused,
}

/// The human verdict. Set once, by a person, through the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Label {
    Benign,
    RealThreat,
    FalsePositive,
}

impl Label {
    pub fn parse(s: &str) -> Option<Label> {
        match s {
            "benign" => Some(Label::Benign),
            "real-threat" | "real_threat" => Some(Label::RealThreat),
            "false-positive" | "false_positive" => Some(Label::FalsePositive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewItem {
    pub id: String,
    pub created: DateTime<Utc>,
    pub source: Source,
    /// Joins this item to the kernel's events for the same agent run.
    pub session_id: String,
    /// One line a human can read in a list.
    pub summary: String,
    /// The full trace record this item came from.
    pub trace: serde_json::Value,
    pub label: Option<Label>,
    pub labeled_at: Option<DateTime<Utc>>,
}

/// A sled tree of review items, newest first.
pub struct ReviewQueue {
    tree: sled::Tree,
}

impl ReviewQueue {
    pub fn open(db_path: &Path) -> Result<Arc<Self>> {
        let db = sled::open(db_path)
            .with_context(|| format!("opening review queue at {}", db_path.display()))?;
        let tree = db.open_tree("review")?;
        Ok(Arc::new(Self { tree }))
    }

    /// Insert an item. The key is reverse-chronological so `iter()` reads
    /// newest first without sorting.
    pub fn push(
        &self,
        source: Source,
        session_id: &str,
        summary: impl Into<String>,
        trace: serde_json::Value,
    ) -> Result<String> {
        let now = Utc::now();
        let id = format!(
            "{:020}-{}",
            u64::MAX - now.timestamp_micros().max(0) as u64,
            &uuid::Uuid::new_v4().to_string()[..8]
        );
        let item = ReviewItem {
            id: id.clone(),
            created: now,
            source,
            session_id: session_id.to_string(),
            summary: summary.into(),
            trace,
            label: None,
            labeled_at: None,
        };
        self.tree
            .insert(id.as_bytes(), serde_json::to_vec(&item)?)?;
        Ok(id)
    }

    pub fn list(&self, limit: usize, unlabeled_only: bool) -> Vec<ReviewItem> {
        self.tree
            .iter()
            .values()
            .filter_map(|v| v.ok())
            .filter_map(|v| serde_json::from_slice::<ReviewItem>(&v).ok())
            .filter(|i| !unlabeled_only || i.label.is_none())
            .take(limit)
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<ReviewItem> {
        self.tree
            .get(id.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice(&v).ok())
    }

    /// Set the human label. Returns false when the id is unknown.
    pub fn label(&self, id: &str, label: Label) -> Result<bool> {
        let Some(mut item) = self.get(id) else {
            return Ok(false);
        };
        item.label = Some(label);
        item.labeled_at = Some(Utc::now());
        self.tree
            .insert(id.as_bytes(), serde_json::to_vec(&item)?)?;
        Ok(true)
    }

    /// Counts for the queue: how much is waiting, and how the labelled items
    /// came out. This is the number that says whether there is yet enough
    /// labelled data to train anything.
    pub fn stats(&self) -> serde_json::Value {
        let (mut total, mut unlabeled, mut benign, mut real, mut fp) = (0, 0, 0, 0, 0);
        for item in self
            .tree
            .iter()
            .values()
            .filter_map(|v| v.ok())
            .filter_map(|v| serde_json::from_slice::<ReviewItem>(&v).ok())
        {
            total += 1;
            match item.label {
                None => unlabeled += 1,
                Some(Label::Benign) => benign += 1,
                Some(Label::RealThreat) => real += 1,
                Some(Label::FalsePositive) => fp += 1,
            }
        }
        serde_json::json!({
            "total": total,
            "unlabeled": unlabeled,
            "benign": benign,
            "real_threat": real,
            "false_positive": fp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_queue() -> Arc<ReviewQueue> {
        let dir = std::env::temp_dir().join(format!("rz-review-test-{}", uuid::Uuid::new_v4()));
        ReviewQueue::open(&dir).expect("open queue")
    }

    #[test]
    fn push_list_and_label_round_trip() {
        let q = temp_queue();
        let id = q
            .push(
                Source::KernelDeny,
                "auto-claude-1",
                "denied open of ~/.aws/credentials",
                serde_json::json!({"event_type": "file_open", "verdict": {"allowed": false}}),
            )
            .unwrap();

        let items = q.list(10, true);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].session_id, "auto-claude-1");
        assert!(items[0].label.is_none());

        assert!(q.label(&id, Label::RealThreat).unwrap());
        assert_eq!(q.get(&id).unwrap().label, Some(Label::RealThreat));
        assert!(
            q.list(10, true).is_empty(),
            "labelled items leave the inbox"
        );
        assert_eq!(q.stats()["real_threat"], 1);
    }

    #[test]
    fn labelling_an_unknown_id_is_not_an_error() {
        let q = temp_queue();
        assert!(!q.label("nope", Label::Benign).unwrap());
    }

    #[test]
    fn newest_item_is_listed_first() {
        let q = temp_queue();
        q.push(Source::CheckFlag, "s1", "first", serde_json::json!({}))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        q.push(Source::CheckFlag, "s2", "second", serde_json::json!({}))
            .unwrap();
        let items = q.list(10, false);
        assert_eq!(items[0].summary, "second");
    }

    #[test]
    fn label_parsing_accepts_both_spellings() {
        assert_eq!(Label::parse("real-threat"), Some(Label::RealThreat));
        assert_eq!(Label::parse("real_threat"), Some(Label::RealThreat));
        assert_eq!(Label::parse("garbage"), None);
    }
}
