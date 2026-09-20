// SPDX-License-Identifier: Apache-2.0
// analyzer/dataset.rs — distillation training-data exporter.
//
// The on-device "security engineer brain" is a TINY language model fine-tuned
// to read a provenance-graph context and emit a verdict. This module captures
// the supervised pairs that fine-tuning needs:
//
//     X = build_graph_rag_prompt(graph)        (the serialized provenance graph)
//     Y = teacher verdict                      (the strong model's judgement)
//
// When a strong teacher is configured (cloud Gemini / Gemma-27B, or local
// Ollama) its verdict becomes the label — i.e. knowledge distillation from a
// large teacher into the tiny edge student. When no teacher is configured we
// still bank the input prompt (teacher = null) so it can be batch-labelled
// offline later. Either way every endpoint quietly accumulates a real-world,
// in-distribution corpus while the product runs.
//
// Safety: this sits next to the detection hot path, so writes are fully
// off-loaded to a dedicated OS thread over a *bounded* channel. If the channel
// is full we DROP the sample (and count it) rather than ever blocking event
// processing. Disk is byte-capped with single-backup rotation so a long-running
// daemon can never fill the volume.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;

use serde::Serialize;

/// Schema version for the JSONL records — bump on any breaking field change so
/// downstream training scripts can refuse mismatched corpora.
pub const DATASET_SCHEMA: u32 = 1;

/// The teacher's judgement that becomes the training label.
#[derive(Clone, Debug, Serialize)]
pub struct TeacherLabel {
    /// Where the label came from: "gemini" | "ollama" | "heuristic" | "none".
    pub source: String,
    /// Concrete model id that produced it (e.g. "gemma-4-27b-it").
    pub model: String,
    pub risk_score: u32,
    /// "allow" | "alert" | "block".
    pub action: String,
    pub explanation: String,
}

/// One supervised example: graph context in, teacher verdict out.
#[derive(Debug, Serialize)]
pub struct TrainingRecord {
    pub schema: u32,
    pub ts: String,
    /// Deterministic heuristic score that gated the sample (useful for
    /// stratified sampling / class balancing during curation).
    pub heuristic_score: u32,
    /// The serialized provenance-graph RAG prompt — the model input.
    pub prompt: String,
    /// Teacher label, or None when no teacher ran (input-only sample).
    pub teacher: Option<TeacherLabel>,
}

/// Handle used by the analyzer to emit samples without touching disk itself.
pub struct DatasetExporter {
    tx: SyncSender<TrainingRecord>,
    captured: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl DatasetExporter {
    /// Spawn the background writer thread. `max_bytes` caps the active file;
    /// on overflow it rotates to `<path>.1` (single backup) and starts fresh.
    pub fn spawn(path: PathBuf, max_bytes: u64) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Bounded queue: bursty event storms must never back-pressure detection.
        let (tx, rx) = sync_channel::<TrainingRecord>(2048);
        let captured = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));

        let cap_w = Arc::clone(&captured);
        std::thread::Builder::new()
            .name("rz-dataset".into())
            .spawn(move || writer_loop(&path, max_bytes, rx, cap_w))?;

        Ok(Self {
            tx,
            captured,
            dropped,
        })
    }

    /// Enqueue a sample. Never blocks; drops (and counts) if the queue is full.
    pub fn record(&self, rec: TrainingRecord) {
        match self.tx.try_send(rec) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// (captured, dropped) counters for status/telemetry.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.captured.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }
}

fn open_append(path: &Path) -> std::io::Result<(BufWriter<File>, u64)> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    Ok((BufWriter::new(file), len))
}

fn writer_loop(
    path: &Path,
    max_bytes: u64,
    rx: std::sync::mpsc::Receiver<TrainingRecord>,
    captured: Arc<AtomicU64>,
) {
    let (mut writer, mut written) = match open_append(path) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(?path, error = %e, "dataset exporter: cannot open file; disabling");
            return;
        }
    };
    tracing::info!(
        ?path,
        max_bytes,
        "dataset exporter: capturing distillation pairs"
    );

    while let Ok(rec) = rx.recv() {
        let mut line = match serde_json::to_string(&rec) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "dataset exporter: serialize failed; skipping sample");
                continue;
            }
        };
        line.push('\n');

        // Rotate before writing if this line would exceed the cap.
        if written + line.len() as u64 > max_bytes {
            if let Err(e) = writer.flush() {
                tracing::warn!(error = %e, "dataset exporter: flush before rotate failed");
            }
            drop(writer);
            let backup = path.with_extension("jsonl.1");
            if let Err(e) = fs::rename(path, &backup) {
                tracing::warn!(error = %e, "dataset exporter: rotate failed; truncating instead");
                let _ = fs::remove_file(path);
            }
            match open_append(path) {
                Ok((w, n)) => {
                    writer = w;
                    written = n;
                }
                Err(e) => {
                    tracing::error!(error = %e, "dataset exporter: reopen after rotate failed; stopping");
                    return;
                }
            }
        }

        if let Err(e) = writer.write_all(line.as_bytes()) {
            tracing::warn!(error = %e, "dataset exporter: write failed");
            continue;
        }
        // Flush each line: low volume relative to disk, and we want samples
        // durable across an unclean daemon shutdown.
        let _ = writer.flush();
        written += line.len() as u64;
        captured.fetch_add(1, Ordering::Relaxed);
    }

    let _ = writer.flush();
    tracing::info!("dataset exporter: channel closed, writer stopped");
}
