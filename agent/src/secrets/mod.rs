// SPDX-License-Identifier: Apache-2.0
// secrets — credential + secret detection in file content and network payloads
// Patterns: AWS keys, GCP keys, OpenAI keys, SSH privkeys, .env tokens, JWTs
// DLP: detect secrets in outbound network payloads (API key routing)

pub mod detector;
pub mod dlp;
pub mod rotation;
