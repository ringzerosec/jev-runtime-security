// SPDX-License-Identifier: Apache-2.0
// platform.rs — helpers for OS-level queries

/// Returns true if the current process is running as root.
pub fn is_elevated() -> bool {
    nix::unistd::Uid::effective().is_root()
}

/// Returns the system hostname.
pub fn hostname() -> String {
    nix::unistd::gethostname()
        .map(|h: std::ffi::OsString| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into())
}
