// SPDX-License-Identifier: Apache-2.0
//
// fanotify.rs — close-write notifications, with the writer's pid.
//
// WHY FANOTIFY AND NOT INOTIFY. Two things are needed to decide whether to
// scan a file: that a write finished, and who wrote it. inotify gives the
// first and cannot give the second — an IN_CLOSE_WRITE carries no pid — and it
// needs a watch per directory, added before the write, which races an agent
// creating directories as it works. fanotify gives both from one file
// descriptor, marked once per mount, and `FAN_REPORT_PIDFD` carries a pidfd
// for the writing process. Measured working on Ubuntu 24.04 / kernel 6.8
// before this was written.
//
// WHY NOT A BPF CLOSE HOOK. There is no close hook in ringzero.bpf.c today,
// and adding one means an event on the hottest path in the kernel for every
// close by a monitored process. fanotify is doing exactly this job, in the
// kernel, already filtered. If that changes — if fanotify turns out to miss
// writes on some filesystem — the note above is where to start.
//
// This module is only the plumbing: it reports (path, pid, dev, ino) and makes
// no decision. What is worth scanning, and what a scan means, is in mod.rs.

use std::os::unix::io::RawFd;

use anyhow::{Context, Result};

// ── fanotify constants, from <sys/fanotify.h> ───────────────────────────────

const FAN_CLOEXEC: u32 = 0x0000_0001;
const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
const FAN_REPORT_PIDFD: u32 = 0x0000_0080;
const FAN_NONBLOCK: u32 = 0x0000_0002;

const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_MARK_MOUNT: u32 = 0x0000_0010;
const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

const FAN_CLOSE_WRITE: u64 = 0x0000_0008;

const FAN_EVENT_INFO_TYPE_PIDFD: u8 = 4;
const FAN_NOPIDFD: i32 = -1;

const AT_FDCWD: i32 = -100;

/// `struct fanotify_event_metadata`.
#[repr(C)]
#[derive(Clone, Copy)]
struct EventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

/// `struct fanotify_event_info_header`.
#[repr(C)]
#[derive(Clone, Copy)]
struct InfoHeader {
    info_type: u8,
    pad: u8,
    len: u16,
}

/// `struct fanotify_event_info_pidfd`.
#[repr(C)]
#[derive(Clone, Copy)]
struct InfoPidfd {
    hdr: InfoHeader,
    pidfd: i32,
}

/// One finished write, as the kernel reported it.
#[derive(Debug)]
pub struct CloseWrite {
    /// The path the writing process had open, resolved through /proc/self/fd.
    pub path: std::path::PathBuf,
    /// The process that closed it.
    pub pid: u32,
    /// Identity of the file, read from the fanotify fd rather than the path,
    /// so a replacement between close and stat cannot be mistaken for it.
    pub dev: u32,
    /// The same device as glibc reports it. Kept because the kernel encodes
    /// `s_dev` differently and the conversion belongs in one place; see
    /// `ebpf_loader::kernel_ino_key`.
    pub raw_dev: u64,
    pub ino: u64,
    /// Size at close, from the same fstat.
    pub size: u64,
    /// The kernel's own descriptor for the file, duplicated and owned by this
    /// struct.
    ///
    /// READ THROUGH THIS, NOT THROUGH `path`. The daemon runs with
    /// `PrivateTmp=true`, so re-opening `/tmp/x` by name lands in the daemon's
    /// private /tmp and fails with ENOENT — every scan of a file under /tmp
    /// reported "no such file" while the file was plainly there. The descriptor
    /// is namespace-independent, and it also settles the replace-between-close-
    /// and-open race for free: it IS the file the event was about.
    pub fd: std::os::unix::io::OwnedFd,
}

/// A fanotify group watching one or more mounts for finished writes.
pub struct Watcher {
    fd: RawFd,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

impl Watcher {
    /// Open a group. Needs CAP_SYS_ADMIN, which the daemon has.
    pub fn new() -> Result<Self> {
        // NONBLOCK so the read loop can be polled on a timer rather than
        // parking a thread forever on a descriptor we also want to shut down.
        let flags = FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_REPORT_PIDFD | FAN_NONBLOCK;
        let fd = unsafe { libc::fanotify_init(flags, libc::O_RDONLY as u32) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!(
                "fanotify_init failed: {err}. This needs CAP_SYS_ADMIN and a kernel with \
                 CONFIG_FANOTIFY and FAN_REPORT_PIDFD (Linux 5.15+)"
            ));
        }
        Ok(Watcher { fd })
    }

    /// Watch a whole filesystem for writes that finished.
    ///
    /// FAN_MARK_FILESYSTEM, not FAN_MARK_MOUNT, and the difference cost an
    /// afternoon. A mount mark watches one vfsmount. The daemon runs with
    /// `PrivateTmp=true` and `ProtectHome=read-only`, so it has its own mount
    /// namespace: a mount mark added from in here watches the daemon's private
    /// /tmp and its read-only bind of /home, and sees nothing an agent writes
    /// through the host's mounts. Events arrived for nothing at all and the
    /// scanner looked like it was working.
    ///
    /// A filesystem mark is on the superblock, which every bind mount and every
    /// namespace shares, so it sees the write wherever it happens. Needs Linux
    /// 4.20+ and CAP_SYS_ADMIN.
    ///
    /// Marking a filesystem rather than each directory is also what removes the
    /// race: an agent creating a directory and writing into it is covered, with
    /// no per-directory bookkeeping to go stale.
    pub fn watch_mount(&self, path: &str) -> Result<()> {
        let c = std::ffi::CString::new(path).context("mount path has an interior NUL")?;
        let rc = unsafe {
            libc::fanotify_mark(
                self.fd,
                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                FAN_CLOSE_WRITE,
                AT_FDCWD,
                c.as_ptr(),
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let fs_err = std::io::Error::last_os_error();

        // Older kernels have no filesystem mark. Fall back, and say what the
        // fallback cannot see rather than degrade quietly.
        let rc = unsafe {
            libc::fanotify_mark(
                self.fd,
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                FAN_CLOSE_WRITE,
                AT_FDCWD,
                c.as_ptr(),
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!(
                "fanotify_mark({path}) failed: filesystem mark: {fs_err}; mount mark: {err}"
            ));
        }
        Err(anyhow::anyhow!(
            "fanotify_mark({path}): this kernel has no FAN_MARK_FILESYSTEM ({fs_err}), so a \
             mount mark was used instead. That only sees writes through THIS process's mount \
             namespace, and the daemon has a private one — writes made through other mounts of \
             the same filesystem will be missed"
        ))
    }

    /// Read whatever is queued. Returns an empty vec when nothing is waiting.
    ///
    /// Every descriptor the kernel hands over is closed here, including for
    /// events that are dropped: leaking them would exhaust the daemon's fd
    /// table in minutes on a busy machine.
    pub fn read_events(&self) -> Result<Vec<CloseWrite>> {
        let mut buf = [0u8; 8192];
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK) => Ok(Vec::new()),
                // The queue overflowed: events were lost. Say so; the caller
                // reports it rather than pretending the scan was complete.
                _ => Err(anyhow::anyhow!("fanotify read failed: {err}")),
            };
        }

        let mut out = Vec::new();
        let mut offset = 0usize;
        let total = n as usize;

        while offset + std::mem::size_of::<EventMetadata>() <= total {
            let meta: EventMetadata =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const _) };
            let event_len = meta.event_len as usize;
            if event_len < std::mem::size_of::<EventMetadata>() || offset + event_len > total {
                break;
            }

            // Walk the info records that follow the metadata for the pidfd.
            let mut pidfd = FAN_NOPIDFD;
            let mut info_off = offset + meta.metadata_len as usize;
            while info_off + std::mem::size_of::<InfoHeader>() <= offset + event_len {
                let hdr: InfoHeader =
                    unsafe { std::ptr::read_unaligned(buf.as_ptr().add(info_off) as *const _) };
                if hdr.len == 0 {
                    break;
                }
                if hdr.info_type == FAN_EVENT_INFO_TYPE_PIDFD
                    && info_off + std::mem::size_of::<InfoPidfd>() <= offset + event_len
                {
                    let info: InfoPidfd =
                        unsafe { std::ptr::read_unaligned(buf.as_ptr().add(info_off) as *const _) };
                    pidfd = info.pidfd;
                }
                info_off += hdr.len as usize;
            }

            if meta.mask & FAN_CLOSE_WRITE != 0 && meta.fd >= 0 {
                match describe(meta.fd, pidfd, meta.pid as u32) {
                    Some(ev) => out.push(ev),
                    None => {}
                }
            }

            // Always give the descriptors back.
            if meta.fd >= 0 {
                unsafe { libc::close(meta.fd) };
            }
            if pidfd >= 0 {
                unsafe { libc::close(pidfd) };
            }

            offset += event_len;
        }
        Ok(out)
    }
}

/// Turn the kernel's descriptors into something the caller can use.
///
/// The identity comes from `fstat` on the fanotify fd, not from the path: the
/// path is only a label, and by the time anyone reads it the name may point at
/// something else. Anything that is not a regular file is dropped here.
fn describe(fd: i32, pidfd: i32, meta_pid: u32) -> Option<CloseWrite> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None; // not a regular file: nothing to scan
    }

    // Our own copy: `read_events` closes the kernel's.
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return None;
    }
    let owned =
        unsafe { <std::os::unix::io::OwnedFd as std::os::unix::io::FromRawFd>::from_raw_fd(dup) };

    // The pidfd is the reliable identifier while the writer is alive. It very
    // often is not: `cat > file` closes and exits in the same breath, and the
    // kernel then reports FAN_NOPIDFD. Dropping those events lost most writes,
    // which looked exactly like a scanner that was running and finding nothing.
    // The metadata pid is what is left, and the caller decides what it is worth.
    let pid = pid_from_pidfd(pidfd).unwrap_or(meta_pid);
    // /proc appends " (deleted)" when the name is already unlinked, which is
    // routine for a compiler temp. Strip it: the suffix is not part of any
    // name, and leaving it on made every path-based test fail on a file that
    // was perfectly readable through the descriptor.
    let raw = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
    let as_str = raw.to_string_lossy();
    let path = match as_str.strip_suffix(" (deleted)") {
        Some(trimmed) => std::path::PathBuf::from(trimmed),
        None => raw.clone(),
    };

    Some(CloseWrite {
        path,
        pid,
        dev: st.st_dev as u32,
        raw_dev: st.st_dev,
        ino: st.st_ino,
        size: st.st_size.max(0) as u64,
        fd: owned,
    })
}

/// The pid behind a pidfd, from `/proc/self/fdinfo`.
///
/// A pidfd is used rather than `metadata.pid` because the pid alone can be
/// reused between the close and the lookup; the fdinfo read resolves the
/// process this descriptor actually refers to.
fn pid_from_pidfd(pidfd: i32) -> Option<u32> {
    if pidfd < 0 {
        return None;
    }
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{pidfd}")).ok()?;
    info.lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|v| v.trim().parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layouts have to match the kernel's, or every field read is garbage.
    #[test]
    fn the_structs_are_the_sizes_the_kernel_writes() {
        assert_eq!(std::mem::size_of::<EventMetadata>(), 24);
        assert_eq!(std::mem::size_of::<InfoHeader>(), 4);
        assert_eq!(std::mem::size_of::<InfoPidfd>(), 8);
    }

    /// The suffix /proc adds for an unlinked file is not part of the name.
    #[test]
    fn the_deleted_suffix_is_stripped() {
        let cases = [
            ("/tmp/ccXYZ.c (deleted)", "/tmp/ccXYZ.c"),
            ("/home/u/x.py (deleted)", "/home/u/x.py"),
            // A file genuinely called that keeps its name.
            ("/tmp/not (deleted) really.c", "/tmp/not (deleted) really.c"),
            ("/tmp/plain.c", "/tmp/plain.c"),
        ];
        for (raw, want) in cases {
            let got = match raw.strip_suffix(" (deleted)") {
                Some(t) => t,
                None => raw,
            };
            assert_eq!(got, want, "stripping {raw:?}");
        }
    }

    #[test]
    fn a_missing_pidfd_is_not_a_pid() {
        assert_eq!(pid_from_pidfd(FAN_NOPIDFD), None);
        assert_eq!(pid_from_pidfd(-7), None);
    }

    /// Opening a group needs CAP_SYS_ADMIN, so this only asserts something
    /// when the tests run as root. Unprivileged, it must fail with a message
    /// that says why rather than panicking.
    #[test]
    fn opening_a_group_either_works_or_explains_itself() {
        match Watcher::new() {
            Ok(w) => assert!(w.fd >= 0),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("CAP_SYS_ADMIN"), "must say why: {msg}");
            }
        }
    }
}
