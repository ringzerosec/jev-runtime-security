// SPDX-License-Identifier: Apache-2.0
//
// build_info — which build is this, exactly.
//
// The crate version alone is not enough: every package carried a static 0.1.0,
// so a tester could be running a binary from days ago and have no way to tell.
// `build-deb.sh` writes the full package version to /usr/lib/ringzero/BUILD,
// and this reads it. When the file is absent — a `cargo run`, a source build —
// the crate version is reported and labelled as such, rather than a number that
// implies a package that was never made.

/// Where the packaging writes the build stamp.
pub const BUILD_FILE: &str = "/usr/lib/ringzero/BUILD";

/// The version to show a human.
pub fn version_string(crate_version: &str) -> String {
    match std::fs::read_to_string(BUILD_FILE) {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => format!("{crate_version} (source build, not packaged)"),
    }
}
