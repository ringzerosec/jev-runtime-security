// SPDX-License-Identifier: Apache-2.0
// analyzer/edge.rs — on-device inference backend for the tiny "security brain".
//
// Loads the fine-tuned FunctionGemma `.litertlm` and runs it fully in-process
// via the official LiteRT-LM Rust binding (the upstream `rust/` crate, a
// cxx-bridge over the C++ engine; Apache-2.0). No Ollama, no cloud, no open
// port. The binding + model are heavy to build, so the real engine lives behind
// the `edge-llm` cargo feature; the default build compiles a stub that fails
// closed with a clear message. The tool-call PARSING that turns the model's
// output into a dispatchable action is backend-independent and always built
// (see analyzer::tool_call) — only the bytes-in/text-out engine is gated here.

use anyhow::Result;

/// Handle to the loaded security brain.
pub struct EdgeBrain {
    #[allow(dead_code)]
    path: String,
    #[cfg(feature = "edge-llm")]
    engine: litert_lm::Engine,
}

impl EdgeBrain {
    /// Load the `.litertlm` model from disk.
    #[cfg(feature = "edge-llm")]
    pub fn load(path: &str) -> Result<Self> {
        if !std::path::Path::new(path).exists() {
            anyhow::bail!("model file not found: {path}");
        }
        // NOTE: pin the exact constructor against the LiteRT-LM rust crate release
        // (Engine builder + a single persistent Session). Kept minimal here.
        let engine = litert_lm::Engine::from_file(path)
            .map_err(|e| anyhow::anyhow!("LiteRT-LM engine load failed: {e}"))?;
        Ok(Self {
            path: path.to_string(),
            engine,
        })
    }

    /// Stub loader for the default build (LiteRT-LM not compiled in).
    #[cfg(not(feature = "edge-llm"))]
    pub fn load(path: &str) -> Result<Self> {
        // Still validate the path so a misconfigured model surfaces as a config
        // error rather than silently behaving like "no backend".
        if !std::path::Path::new(path).exists() {
            anyhow::bail!("model file not found: {path}");
        }
        anyhow::bail!(
            "edge LiteRT-LM backend not compiled into this binary \
             (rebuild the daemon with --features edge-llm)"
        )
    }

    /// Run inference: system instruction + serialized graph context in, raw
    /// model text out (expected to be a single tool call — parsed by the caller).
    #[cfg(feature = "edge-llm")]
    pub fn generate(&self, system: &str, user: &str) -> Result<String> {
        let mut session = self.engine.create_session()?;
        session.set_system_instruction(system)?;
        let out = session.generate(user)?;
        Ok(out)
    }

    #[cfg(not(feature = "edge-llm"))]
    pub fn generate(&self, _system: &str, _user: &str) -> Result<String> {
        anyhow::bail!("edge LiteRT-LM backend not compiled in")
    }
}
