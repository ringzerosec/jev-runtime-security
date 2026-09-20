// SPDX-License-Identifier: Apache-2.0
// session/namespace.rs — Mount-namespace JIT access control
//
// When an AI agent runs inside a Linux mount+PID namespace (via `rz sandbox`),
// sensitive files are hidden by bind-mounting an empty deny-marker over them.
//
// These helpers use `nsenter` to enter the sandbox's mount namespace and
// unmount (grant) or re-mount (revoke) the bind-mount, giving the daemon
// fine-grained, time-boxed file access inside the sandbox.

/// Restore access to a path inside a sandboxed process's mount namespace.
/// Uses nsenter to enter the target PID's mount namespace and unmount the bind-mount.
pub async fn grant_namespace_access(pid: u32, path: &str) -> Result<(), String> {
    use tokio::process::Command;
    check_scope_path(path)?;
    check_sandboxed(pid)?;
    let status = Command::new("nsenter")
        .args([
            "--mount",
            &format!("--target={}", pid),
            "--",
            "umount",
            "--",
            path,
        ])
        .status()
        .await
        .map_err(|e| format!("nsenter failed: {}", e))?;
    if status.success() {
        tracing::info!(pid, path, "Namespace access granted: unmounted bind-mount");
        Ok(())
    } else {
        Err(format!("nsenter umount failed with status {}", status))
    }
}

/// Revoke access by re-applying the bind-mount inside the namespace.
pub async fn revoke_namespace_access(pid: u32, path: &str) -> Result<(), String> {
    use tokio::process::Command;
    let marker = "/var/lib/ringzero/.deny-marker";
    check_scope_path(path)?;
    check_sandboxed(pid)?;
    let status = Command::new("nsenter")
        .args([
            "--mount",
            &format!("--target={}", pid),
            "--",
            "mount",
            "--bind",
            "--",
            marker,
            path,
        ])
        .status()
        .await
        .map_err(|e| format!("nsenter failed: {}", e))?;
    if status.success() {
        tracing::info!(pid, path, "Namespace access revoked: re-applied bind-mount");
        Ok(())
    } else {
        Err(format!(
            "nsenter mount --bind failed with status {}",
            status
        ))
    }
}

/// A JIT scope is an absolute filesystem path supplied by an API caller. Reject
/// anything that could be read as a mount/umount option or is not a real path.
fn check_scope_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.contains('\0') || path.len() > 4096 {
        return Err(format!(
            "invalid scope path {:?}: must be an absolute path",
            path
        ));
    }
    Ok(())
}

/// Only ever (un)mount inside a *separate* mount namespace. Session PIDs can be
/// attached by API callers, so without this check a caller could point the
/// daemon at a host-namespace PID and have root umount/bind-mount host paths.
fn check_sandboxed(pid: u32) -> Result<(), String> {
    let own = std::fs::read_link("/proc/self/ns/mnt").map_err(|e| format!("own mnt ns: {e}"))?;
    let target = std::fs::read_link(format!("/proc/{pid}/ns/mnt"))
        .map_err(|e| format!("pid {pid} mnt ns: {e}"))?;
    if own == target {
        return Err(format!(
            "pid {pid} shares the host mount namespace — refusing to modify mounts"
        ));
    }
    Ok(())
}
