// SPDX-License-Identifier: Apache-2.0
// fscache.rs — one-shot file reads that don't pollute the page cache.
//
// The scanner (YARA/pattern scans, supply-chain, skill-surface, secret
// detection, injection scans) reads each file exactly once: scan it, then never
// touch it again. Left to the default `std::fs::read*`, every byte the scanner
// touches lingers in the daemon cgroup's page cache. That memory is reclaimable,
// but it's exactly what inflates the daemon's apparent RSS/`MemoryCurrent` in
// `systemctl status` and monitoring — the "why is it using so much RAM" number.
//
// These helpers read the whole file, then advise the kernel to drop that file's
// pages from the page cache (POSIX_FADV_DONTNEED on Linux). Return types match
// `std::fs::read` / `std::fs::read_to_string` so call sites are drop-in.
//
// Note: this only affects pages *we* brought in for a one-shot scan; it does not
// touch files that are legitimately hot elsewhere. On non-Linux it's a no-op and
// behaves exactly like the std equivalents.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

fn drop_from_cache(file: &File) {
    use std::os::unix::io::AsRawFd;
    // offset 0, len 0 == "from start to end of file". Best-effort; the pages are
    // clean (read-only scan) so the kernel can evict them immediately. Ignore the
    // return code — failing to drop cache must never fail a scan.
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
    }
}

/// Like `std::fs::read`, but drops the file from the page cache afterward.
pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    drop_from_cache(&file);
    Ok(buf)
}

/// Like `std::fs::read_to_string`, but drops the file from the page cache after.
pub fn read_to_string(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut s = String::new();
    file.read_to_string(&mut s)?;
    drop_from_cache(&file);
    Ok(s)
}
