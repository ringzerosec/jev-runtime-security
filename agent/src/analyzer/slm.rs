// SPDX-License-Identifier: Apache-2.0
// analyzer/slm.rs — Security analyzer using Graph RAG + LLM inference
//
// Two inference modes:
//   1. Local  — Ollama (any model: gemma3, llama3, etc.)
//   2. Cloud  — Google Gemini API (gemma-4-27b-it or gemini models)
//
// The analyzer receives a provenance graph, serializes it into a structured
// prompt (Graph RAG context), sends it to the model, and parses a verdict.
//
// The SLM only fires when the deterministic heuristic score crosses the
// configured threshold — it is NOT the always-on detection layer.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use crate::analyzer::rule_compiler::L0Rule;
use crate::ebpf_loader::EbpfCommand;

use crate::analyzer::dataset::{DatasetExporter, TeacherLabel, TrainingRecord, DATASET_SCHEMA};
use crate::analyzer::graph::{build_graph_rag_prompt, ProvenanceGraph};

/// SLM inference mode — configurable via daemon.toml [slm] section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlmMode {
    Off,
    Local,
    Cloud,
    /// Fully on-device: the fine-tuned tiny FunctionGemma "security brain" runs
    /// in-process via the LiteRT-LM Rust binding and emits a structured tool
    /// call (analyzer::tool_call). No Ollama, no cloud, no open port.
    Edge,
}

impl Default for SlmMode {
    fn default() -> Self {
        SlmMode::Off
    }
}

/// Configuration for the SLM analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SlmConfig {
    pub mode: SlmMode,
    /// Ollama model name for local inference (e.g. "gemma3:4b").
    pub model_path: Option<String>,
    /// Gemini model ID for cloud inference (e.g. "gemma-4-27b-it").
    pub cloud_model: Option<String>,
    /// Path to the fine-tuned `.litertlm` security brain for Edge mode.
    pub edge_model_path: Option<String>,
    /// Gemini API key (overridden by GEMINI_API_KEY env var).
    pub gemini_api_key: Option<String>,
    /// Maximum events to include in analysis context.
    pub context_window: usize,
    /// Minimum heuristic score before triggering SLM analysis (avoid wasting compute).
    pub score_threshold: u32,

    /// Capture (graph context → teacher verdict) pairs as a distillation corpus
    /// for fine-tuning the tiny on-device student model. Runs independently of
    /// `mode`/`score_threshold` so benign + low-score samples are collected too.
    pub capture_dataset: bool,
    /// Where the JSONL corpus is written (default: platform data dir).
    pub dataset_path: Option<String>,
    /// Byte cap (in MiB) for the active corpus file before single-backup rotation.
    pub dataset_max_mb: Option<u64>,
}

impl Default for SlmConfig {
    fn default() -> Self {
        SlmConfig {
            mode: SlmMode::Off,
            model_path: None,
            cloud_model: Some("gemma-4-27b-it".to_string()),
            edge_model_path: None,
            gemini_api_key: None,
            context_window: 20,
            score_threshold: 40,
            capture_dataset: false,
            dataset_path: None,
            dataset_max_mb: None,
        }
    }
}

/// Result of SLM security analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SlmVerdict {
    /// Risk score 0-100
    pub risk_score: u32,
    /// Natural language explanation
    pub explanation: String,
    /// Recommended action
    pub action: SlmAction,
    /// Model used for inference
    pub model: String,
    /// Inference latency in milliseconds
    pub latency_ms: u64,
    /// Audit trail of the compile step: what L0 rules were installed, and what
    /// was refused and why. Empty for advisory/free-text verdicts; populated
    /// only when a structured tool call programs the kernel.
    #[serde(default)]
    pub compiled_rules: Vec<String>,
    /// Executable, platform-neutral L0 rules compiled from the judgment. The
    /// Linux daemon translates these into eBPF commands in `analyze_graph`.
    #[serde(default)]
    pub l0_rules: Vec<L0Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum SlmAction {
    Allow,
    Alert,
    Block,
}

/// The SLM analyzer — holds model state and provides async inference.
#[allow(dead_code)]
pub struct SlmAnalyzer {
    config: SlmConfig,
    status: Arc<RwLock<SlmStatus>>,
    /// Optional distillation-corpus writer (None unless capture_dataset = true).
    exporter: Option<Arc<DatasetExporter>>,
    /// Loaded on-device brain (Some only in Edge mode with a usable model).
    edge_brain: Option<Arc<crate::analyzer::edge::EdgeBrain>>,
    /// L0 sender: compiled eBPF rules from a judgment are pushed here so the
    /// slow brain programs the fast kernel reflexes. Set after the eBPF loader
    /// starts (`attach_l0`); None until then (and on non-root). Linux-only —
    /// eBPF is the only L0 enforcement backend.
    l0: Arc<RwLock<Option<mpsc::Sender<EbpfCommand>>>>,
}

/// System instruction sent to the edge brain — kept in sync with
/// ml/curate.py / ml/label_offline.py so train-time and serve-time match.
const EDGE_SYSTEM_PROMPT: &str = "You are Ring Zero's on-device security engineer. \
You are given a provenance graph describing an AI agent's recent kernel-level behavior \
(processes, file access, network, LLM responses, attack chains) and its expected baseline. \
Decide the single correct defensive action and call exactly one tool: \
allow, alert, block, quarantine, or escalate.";

/// Default on-disk location for the fine-tuned security brain.
fn default_edge_model_path() -> String {
    "/var/lib/ringzero/models/security-brain.litertlm".to_string()
}

/// Default corpus location — alongside the daemon's other state.
fn default_dataset_path() -> String {
    "/var/lib/ringzero/dataset/security-graph.jsonl".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SlmStatus {
    pub mode: SlmMode,
    pub loaded: bool,
    pub model_name: Option<String>,
    pub total_queries: u64,
    pub avg_latency_ms: f64,
}

const GEMINI_API_BASE: &str = "https://generativelanguage.googleapis.com/v1beta/models";

#[allow(dead_code)]
impl SlmAnalyzer {
    pub fn new(config: SlmConfig) -> Self {
        let mode = config.mode.clone();
        let exporter = if config.capture_dataset {
            let path = config
                .dataset_path
                .clone()
                .unwrap_or_else(default_dataset_path);
            let max_bytes = config
                .dataset_max_mb
                .unwrap_or(256)
                .saturating_mul(1024 * 1024);
            match DatasetExporter::spawn(path.clone().into(), max_bytes) {
                Ok(exp) => Some(Arc::new(exp)),
                Err(e) => {
                    tracing::error!(path, error = %e, "dataset capture requested but exporter failed to start");
                    None
                }
            }
        } else {
            None
        };
        let edge_brain = if config.mode == SlmMode::Edge {
            let path = config
                .edge_model_path
                .clone()
                .unwrap_or_else(default_edge_model_path);
            match crate::analyzer::edge::EdgeBrain::load(&path) {
                Ok(b) => {
                    tracing::info!(path, "edge security brain loaded");
                    Some(Arc::new(b))
                }
                Err(e) => {
                    tracing::warn!(path, error = %e, "edge security brain unavailable");
                    None
                }
            }
        } else {
            None
        };
        Self {
            config,
            status: Arc::new(RwLock::new(SlmStatus {
                mode,
                loaded: false,
                model_name: None,
                total_queries: 0,
                avg_latency_ms: 0.0,
            })),
            exporter,
            edge_brain,
            l0: Arc::new(RwLock::new(None)),
        }
    }

    /// Wire the eBPF command channel so compiled judgments program L0 reflexes.
    /// Called once the kernel loader is up (the daemon holds the same sender).
    pub async fn attach_l0(&self, tx: mpsc::Sender<EbpfCommand>) {
        *self.l0.write().await = Some(tx);
    }

    /// Resolve the Gemini API key: env var takes priority over config.
    fn gemini_api_key(&self) -> Option<String> {
        std::env::var("GEMINI_API_KEY")
            .ok()
            .or_else(|| self.config.gemini_api_key.clone())
    }

    /// Initialize the analyzer — verify ollama connectivity or Gemini API key.
    pub async fn init(&self) -> anyhow::Result<()> {
        match self.config.mode {
            SlmMode::Off => {
                tracing::info!("SLM analyzer disabled");
            }
            SlmMode::Local => {
                let model = self.config.model_path.as_deref().unwrap_or("gemma3:4b");
                let endpoint = "http://127.0.0.1:11434/api/tags".to_string();
                match reqwest::Client::new()
                    .get(&endpoint)
                    .timeout(std::time::Duration::from_secs(5))
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        tracing::info!(model, "SLM local mode — ollama connected");
                        let mut status = self.status.write().await;
                        status.loaded = true;
                        status.model_name = Some(model.to_string());
                    }
                    _ => {
                        tracing::warn!("SLM local mode — ollama not reachable at 127.0.0.1:11434");
                        let mut status = self.status.write().await;
                        status.loaded = false;
                        status.model_name = Some(format!("{} (ollama offline)", model));
                    }
                }
            }
            SlmMode::Cloud => {
                let model = self
                    .config
                    .cloud_model
                    .as_deref()
                    .unwrap_or("gemma-4-27b-it");
                if self.gemini_api_key().is_some() {
                    tracing::info!(model, "SLM cloud mode — Gemini API configured");
                    let mut status = self.status.write().await;
                    status.loaded = true;
                    status.model_name = Some(model.to_string());
                } else {
                    tracing::warn!("SLM cloud mode — no GEMINI_API_KEY set (env var or config)");
                    let mut status = self.status.write().await;
                    status.loaded = false;
                    status.model_name = Some(format!("{} (no api key)", model));
                }
            }
            SlmMode::Edge => {
                let mut status = self.status.write().await;
                if self.edge_brain.is_some() {
                    tracing::info!("SLM edge mode — on-device security brain ready (LiteRT-LM)");
                    status.loaded = true;
                    status.model_name = Some("functiongemma-rz".to_string());
                } else {
                    tracing::warn!(
                        "SLM edge mode — security brain not loaded (see earlier warning)"
                    );
                    status.loaded = false;
                    status.model_name = Some("functiongemma-rz (unavailable)".to_string());
                }
            }
        }
        Ok(())
    }

    /// Analyze a provenance subgraph using Graph RAG context.
    /// This is the primary inference path — sends the full graph topology
    /// (events + edges + supply chain context) to the model.
    pub async fn analyze_graph(
        &self,
        graph: &ProvenanceGraph,
        session_policy: Option<&crate::analyzer::observer::SessionPolicy>,
        heuristic_score: u32,
    ) -> Option<SlmVerdict> {
        // Inference fires only when enabled AND the heuristic gate is crossed.
        // Dataset capture is independent of both gates: whenever the daemon
        // bothers to build a provenance graph (baseline violations, high-risk
        // behavior, attack chains) we bank the sample even if SLM is Off or the
        // score is below the inference threshold. These analysis points are the
        // contested cases where the tiny student most needs the teacher's
        // judgement; bulk-benign examples are sampled offline during curation.
        let capture = self.exporter.is_some();
        let want_inference =
            self.config.mode != SlmMode::Off && heuristic_score >= self.config.score_threshold;

        if !capture && !want_inference {
            return None;
        }

        let prompt = build_graph_rag_prompt(graph, session_policy);

        let verdict = if want_inference {
            match self.config.mode {
                SlmMode::Local => {
                    if self.status.read().await.loaded {
                        let model = self.config.model_path.as_deref().unwrap_or("gemma3:4b");
                        self.call_ollama(model, &prompt).await
                    } else {
                        tracing::debug!("SLM local: ollama not available for graph analysis");
                        None
                    }
                }
                SlmMode::Cloud => {
                    if self.status.read().await.loaded {
                        self.call_gemini(&prompt).await
                    } else {
                        tracing::debug!("SLM cloud: Gemini API not configured");
                        None
                    }
                }
                SlmMode::Edge => {
                    if self.status.read().await.loaded {
                        self.call_edge(&prompt).await
                    } else {
                        tracing::debug!("SLM edge: security brain not loaded");
                        None
                    }
                }
                SlmMode::Off => None,
            }
        } else {
            None
        };

        if let Some(ref v) = verdict {
            let mut status = self.status.write().await;
            status.total_queries += 1;
            let n = status.total_queries as f64;
            status.avg_latency_ms = status.avg_latency_ms * (n - 1.0) / n + v.latency_ms as f64 / n;
        }

        // Distillation capture: graph context in, teacher verdict (when one ran)
        // as the label. No teacher → input-only sample for offline labelling.
        if let Some(exp) = &self.exporter {
            let teacher = verdict.as_ref().map(|v| TeacherLabel {
                source: match self.config.mode {
                    SlmMode::Cloud => "gemini",
                    SlmMode::Local => "ollama",
                    SlmMode::Edge => "edge",
                    SlmMode::Off => "none",
                }
                .to_string(),
                model: v.model.clone(),
                risk_score: v.risk_score,
                action: match v.action {
                    SlmAction::Allow => "allow",
                    SlmAction::Alert => "alert",
                    SlmAction::Block => "block",
                }
                .to_string(),
                explanation: v.explanation.clone(),
            });
            exp.record(TrainingRecord {
                schema: DATASET_SCHEMA,
                ts: chrono::Utc::now().to_rfc3339(),
                heuristic_score,
                prompt,
                teacher,
            });
        }

        // A judgment that compiled into L0 rules programs the kernel reflexes
        // now. try_send so a slow/backed-up
        // eBPF channel never stalls analysis — a dropped rule is re-derivable on
        // the next occurrence, but a blocked analyzer is not.
        if let Some(ref v) = verdict {
            if !v.l0_rules.is_empty() {
                if let Some(tx) = self.l0.read().await.as_ref() {
                    for rule in &v.l0_rules {
                        let cmd = match rule {
                            L0Rule::BlockFile(p) => EbpfCommand::BlockFile(p.clone()),
                            L0Rule::BlockIp(ip) => EbpfCommand::BlockIp(ip.clone()),
                            L0Rule::ContainPid(pid) => EbpfCommand::ContainPid(*pid),
                        };
                        match tx.try_send(cmd) {
                            Ok(()) => tracing::info!(?rule, "edge brain compiled L0 eBPF rule"),
                            Err(e) => {
                                tracing::warn!(?rule, error = %e, "failed to push compiled L0 rule")
                            }
                        }
                    }
                } else {
                    tracing::debug!(
                        rules = v.l0_rules.len(),
                        "judgment compiled L0 rules but no eBPF channel attached (non-root / loader down)"
                    );
                }
            }
        }

        verdict
    }

    /// Run the on-device security brain (Edge mode). The model emits a single
    /// FunctionGemma tool call; we parse it into a dispatchable verdict. CPU
    /// inference runs on a blocking thread so it never stalls the async runtime.
    async fn call_edge(&self, prompt: &str) -> Option<SlmVerdict> {
        let brain = Arc::clone(self.edge_brain.as_ref()?);
        let sys = EDGE_SYSTEM_PROMPT.to_string();
        let user = prompt.to_string();
        let start = std::time::Instant::now();

        let gen = tokio::task::spawn_blocking(move || brain.generate(&sys, &user)).await;
        let text = match gen {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "edge brain inference failed");
                return None;
            }
            Err(e) => {
                tracing::warn!(error = %e, "edge brain task panicked");
                return None;
            }
        };
        let latency_ms = start.elapsed().as_millis() as u64;

        match crate::analyzer::tool_call::parse_tool_call(&text) {
            Ok(call) => {
                tracing::info!(
                    tool = call.name(),
                    risk = call.risk_score(),
                    latency_ms,
                    "edge brain emitted tool call"
                );
                Some(call.to_verdict("functiongemma-rz", latency_ms))
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    output = %truncate_log(&text, 200),
                    "edge brain output was not a valid tool call"
                );
                None
            }
        }
    }

    /// Call Google Gemini API (generativelanguage.googleapis.com).
    /// Works with gemma-4-27b-it, gemini-2.0-flash, etc.
    async fn call_gemini(&self, prompt: &str) -> Option<SlmVerdict> {
        let api_key = self.gemini_api_key()?;
        let model = self
            .config
            .cloud_model
            .as_deref()
            .unwrap_or("gemma-4-27b-it");

        let url = format!(
            "{}/{}:generateContent?key={}",
            GEMINI_API_BASE, model, api_key
        );

        let body = serde_json::json!({
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 512,
            },
            "safetySettings": [
                { "category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE" },
                { "category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE" },
                { "category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE" },
                { "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE" },
            ]
        });

        let start = std::time::Instant::now();

        let resp = match reqwest::Client::new()
            .post(&url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(err = %e, model, "SLM cloud: Gemini API request failed");
                return None;
            }
        };

        let latency = start.elapsed().as_millis() as u64;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                status = %status,
                body = %truncate_log(&body, 200),
                model,
                "SLM cloud: Gemini API non-success"
            );
            return None;
        }

        let data: serde_json::Value = match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(err = %e, "SLM cloud: failed to parse Gemini response");
                return None;
            }
        };

        // Extract text from Gemini response:
        // { "candidates": [{ "content": { "parts": [{ "text": "..." }] } }] }
        let response_text = data
            .get("candidates")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("content"))
            .and_then(|c| c.get("parts"))
            .and_then(|p| p.get(0))
            .and_then(|p| p.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("");

        if response_text.is_empty() {
            tracing::warn!(model, "SLM cloud: empty response from Gemini");
            return None;
        }

        let (action, risk_score) = parse_verdict(response_text);

        tracing::info!(
            verdict = ?action,
            risk = risk_score,
            latency_ms = latency,
            model,
            "SLM cloud: Gemini analysis complete"
        );

        Some(SlmVerdict {
            risk_score,
            explanation: response_text.to_string(),
            action,
            model: model.to_string(),
            latency_ms: latency,
            // Free-text cloud/local paths produce no structured target, so they
            // program no L0 rules — only the edge tool-call path compiles policy.
            compiled_rules: Vec::new(),
            l0_rules: Vec::new(),
        })
    }

    /// Call ollama HTTP API and parse the response into an SlmVerdict.
    async fn call_ollama(&self, model: &str, prompt: &str) -> Option<SlmVerdict> {
        let start = std::time::Instant::now();

        let body = serde_json::json!({
            "model": model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0.1,
                "num_predict": 512,
            }
        });

        let resp = match reqwest::Client::new()
            .post("http://127.0.0.1:11434/api/generate")
            .json(&body)
            .timeout(std::time::Duration::from_secs(120))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(err = %e, "SLM local: ollama request failed");
                return None;
            }
        };

        let latency = start.elapsed().as_millis() as u64;

        let data: serde_json::Value = match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(err = %e, "SLM local: failed to parse ollama response");
                return None;
            }
        };

        let response_text = data.get("response").and_then(|v| v.as_str()).unwrap_or("");

        if response_text.is_empty() {
            tracing::warn!("SLM local: empty response from ollama");
            return None;
        }

        let (action, risk_score) = parse_verdict(response_text);

        tracing::info!(
            verdict = ?action,
            risk = risk_score,
            latency_ms = latency,
            model,
            "SLM local: analysis complete"
        );

        Some(SlmVerdict {
            risk_score,
            explanation: response_text.to_string(),
            action,
            model: model.to_string(),
            latency_ms: latency,
            // Free-text cloud/local paths produce no structured target, so they
            // program no L0 rules — only the edge tool-call path compiles policy.
            compiled_rules: Vec::new(),
            l0_rules: Vec::new(),
        })
    }

    /// Get current analyzer status.
    pub async fn status(&self) -> SlmStatus {
        self.status.read().await.clone()
    }
}

// ── Response parsing ────────────────────────────────────────────────────────

/// Parse VERDICT / Risk Score / Action from model response text.
fn parse_verdict(text: &str) -> (SlmAction, u32) {
    let upper = text.to_uppercase();
    if upper.contains("VERDICT: MALICIOUS") || upper.contains("VERDICT:MALICIOUS") {
        (SlmAction::Block, extract_risk_score(text).unwrap_or(85))
    } else if upper.contains("VERDICT: SUSPICIOUS") || upper.contains("VERDICT:SUSPICIOUS") {
        (SlmAction::Alert, extract_risk_score(text).unwrap_or(45))
    } else if upper.contains("VERDICT: BENIGN") || upper.contains("VERDICT:BENIGN") {
        (SlmAction::Allow, extract_risk_score(text).unwrap_or(5))
    } else if upper.contains("MALICIOUS") {
        (SlmAction::Block, extract_risk_score(text).unwrap_or(75))
    } else if upper.contains("SUSPICIOUS") {
        (SlmAction::Alert, extract_risk_score(text).unwrap_or(40))
    } else {
        (SlmAction::Allow, extract_risk_score(text).unwrap_or(10))
    }
}

fn extract_risk_score(text: &str) -> Option<u32> {
    for line in text.lines() {
        let upper = line.to_uppercase();
        if upper.contains("RISK SCORE") || upper.contains("RISK:") {
            for word in line.split(|c: char| !c.is_ascii_digit()) {
                if let Ok(n) = word.parse::<u32>() {
                    if n <= 100 {
                        return Some(n);
                    }
                }
            }
        }
    }
    None
}

fn truncate_log(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_off() {
        let cfg = SlmConfig::default();
        assert_eq!(cfg.mode, SlmMode::Off);
        assert_eq!(cfg.score_threshold, 40);
        assert_eq!(cfg.context_window, 20);
        assert_eq!(cfg.cloud_model.as_deref(), Some("gemma-4-27b-it"));
    }

    #[tokio::test]
    async fn off_mode_returns_none() {
        let analyzer = SlmAnalyzer::new(SlmConfig::default());
        let graph = ProvenanceGraph::new();
        let result = analyzer.analyze_graph(&graph, None, 100).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn below_threshold_returns_none() {
        let cfg = SlmConfig {
            mode: SlmMode::Cloud,
            score_threshold: 50,
            ..Default::default()
        };
        let analyzer = SlmAnalyzer::new(cfg);
        let graph = ProvenanceGraph::new();
        // Score 30 < threshold 50 → None
        let result = analyzer.analyze_graph(&graph, None, 30).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn capture_writes_jsonl_even_when_off() {
        // Even with SLM Off (no teacher), enabling capture must bank the graph
        // context as an input-only sample for offline labelling.
        let path =
            std::env::temp_dir().join(format!("rz-dataset-test-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let cfg = SlmConfig {
            mode: SlmMode::Off,
            capture_dataset: true,
            dataset_path: Some(path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let analyzer = SlmAnalyzer::new(cfg);
        let graph = ProvenanceGraph::new();

        // Off mode → verdict is None, but capture should still fire.
        let result = analyzer.analyze_graph(&graph, None, 100).await;
        assert!(result.is_none());

        // Writer runs on its own thread; poll briefly for the flushed line.
        let mut contents = String::new();
        for _ in 0..50 {
            if let Ok(s) = std::fs::read_to_string(&path) {
                if !s.trim().is_empty() {
                    contents = s;
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(!contents.trim().is_empty(), "no dataset record was written");

        let line = contents.lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).expect("record is valid JSON");
        assert_eq!(v["schema"], DATASET_SCHEMA);
        assert_eq!(v["heuristic_score"], 100);
        assert!(v["prompt"].is_string(), "prompt must be present");
        assert!(
            v["teacher"].is_null(),
            "no teacher configured → teacher null"
        );
        assert!(v["ts"].is_string());

        let _ = std::fs::remove_file(&path);
    }

    // Live demo of the daemon's real SLM path against a credential-exfil graph.
    // Ignored by default (needs network + GEMINI_API_KEY). Run with:
    //   GEMINI_API_KEY=… cargo test -p daemon --bin ringzero-daemon \
    //       analyzer::slm::tests::cloud_live_demo -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn cloud_live_demo() {
        use crate::common::event::{EventKind, SecurityEvent};
        use chrono::Utc;

        if std::env::var("GEMINI_API_KEY").is_err() {
            return; // needs a live API key
        }

        let mk =
            |i: u32, kind: EventKind, process: &str, target: &str, allowed: bool| SecurityEvent {
                id: format!("5641-{i}"),
                kind,
                pid: 5641,
                uid: 1000,
                process: process.to_string(),
                target: target.to_string(),
                allowed,
                reason: None,
                timestamp: Utc::now(),
                ppid: Some(1),
                parent_process: Some("node".to_string()),
                llm_context: None,
                extra: None,
            };

        // A coding agent reads an SSH private key, resolves an external host,
        // then sends data out — the classic credential-exfiltration chain.
        let events = vec![
            mk(1, EventKind::ProcessExec, "node", "/usr/bin/curl", true),
            mk(
                2,
                EventKind::FileOpen,
                "curl",
                "/home/rooot/.ssh/id_rsa",
                false,
            ),
            mk(
                3,
                EventKind::DnsQuery,
                "curl",
                "exfil.evil-c2.example.com",
                true,
            ),
            mk(
                4,
                EventKind::NetworkConnect,
                "curl",
                "203.0.113.9:443",
                true,
            ),
            mk(5, EventKind::NetworkSend, "curl", "203.0.113.9:443", true),
        ];

        let graph = ProvenanceGraph::from_events(&events, 20);

        let cfg = SlmConfig {
            mode: SlmMode::Cloud,
            cloud_model: Some("gemini-2.5-flash-lite".to_string()),
            score_threshold: 0,
            ..Default::default()
        };
        let analyzer = SlmAnalyzer::new(cfg);
        analyzer.init().await.expect("init");

        let verdict = analyzer
            .analyze_graph(&graph, None, 90)
            .await
            .expect("expected a verdict from cloud SLM");

        // A coding agent reading an SSH key + outbound send must not be allowed.
        assert_ne!(
            verdict.action,
            SlmAction::Allow,
            "exfil chain should not be allowed"
        );
    }

    #[test]
    fn parse_verdict_malicious() {
        let (action, score) = parse_verdict(
            "VERDICT: MALICIOUS\nRisk Score: 92/100\nAction: BLOCK\nANALYSIS: credential exfil",
        );
        assert_eq!(action, SlmAction::Block);
        assert_eq!(score, 92);
    }

    #[test]
    fn parse_verdict_benign() {
        let (action, score) = parse_verdict(
            "VERDICT: BENIGN\nRisk Score: 5/100\nAction: ALLOW\nANALYSIS: normal dev workflow",
        );
        assert_eq!(action, SlmAction::Allow);
        assert_eq!(score, 5);
    }

    #[test]
    fn parse_verdict_suspicious() {
        let (action, score) =
            parse_verdict("VERDICT: SUSPICIOUS\nRisk Score: 55/100\nAction: ALERT");
        assert_eq!(action, SlmAction::Alert);
        assert_eq!(score, 55);
    }

    #[test]
    fn parse_verdict_fallback() {
        let (action, _) = parse_verdict("This is just some random text without a verdict");
        assert_eq!(action, SlmAction::Allow);
    }
}
