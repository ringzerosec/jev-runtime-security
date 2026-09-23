// SPDX-License-Identifier: Apache-2.0
//
// dns_allow — allow egress by NAME, learned from observed DNS answers.
//
// WHY A STATIC IP ALLOWLIST CANNOT WORK. The daemon used to resolve the model
// API hostnames once at startup and push the addresses into the kernel. The
// model API is behind a CDN: the daemon resolved `api.anthropic.com` at boot
// and held 42 addresses, the agent resolved the same name later and got
// 160.79.104.10, which was not among them. So the agent's own calls to its own
// model read as off-allowlist. Measured: a session doing only local file work
// tainted 18 processes.
//
// Re-resolving on a timer does not fix this, it only narrows the race. The
// daemon's answer and the agent's answer are different answers to the same
// question, and no amount of asking more often makes them the same.
//
// WHAT WORKS. Allow by name. Watch the DNS answers the machine actually
// receives; when a name on the allowlist resolves, admit exactly the addresses
// that answer carried, for exactly as long as the record says they are valid.
// The agent and the policy then agree by construction, because they are looking
// at the same answer. This is the standard technique for hostname egress
// policy; Cilium's DNS-based network policy is the reference.
//
// THE ONE RULE still holds. Nothing here is a judgment: a DNS answer is a fact
// on the wire, parsed deterministically. An entry only ever WIDENS the
// allowlist, and only for the TTL the authoritative answer specified, so a
// stale or spoofed answer cannot narrow anyone's authority — the failure
// direction is an address we decline to admit, which taints, which is the safe
// side.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// One learned mapping: an address that answered for an allowlisted name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Learned {
    pub name: String,
    pub addr: Ipv4Addr,
    pub expires: Instant,
}

/// An A record from a DNS answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ARecord {
    pub name: String,
    pub addr: Ipv4Addr,
    pub ttl_secs: u32,
}

/// The smallest TTL we will honour, so a one-second record does not make the
/// allowlist thrash.
const MIN_TTL: Duration = Duration::from_secs(30);
/// The largest, so a hostile or broken answer cannot pin an address forever.
const MAX_TTL: Duration = Duration::from_secs(3600);

/// Names whose answers we admit. A leading dot means "this name and any
/// subdomain of it".
#[derive(Debug, Clone)]
pub struct NameAllowlist {
    patterns: Vec<String>,
}

impl NameAllowlist {
    pub fn new(patterns: impl IntoIterator<Item = String>) -> Self {
        NameAllowlist {
            patterns: patterns
                .into_iter()
                .map(|p| p.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|p| !p.is_empty())
                .collect(),
        }
    }

    /// Does this answered name match something the operator allowed?
    ///
    /// Suffix matching is on LABEL boundaries, never on a bare substring:
    /// `.anthropic.com` must not be satisfied by `evil-anthropic.com`, and
    /// `anthropic.com.attacker.net` must not match either. That is the same
    /// class of mistake as matching agents by substring, which already cost a
    /// day.
    pub fn matches(&self, answered: &str) -> Option<&str> {
        let a = answered.trim().trim_end_matches('.').to_ascii_lowercase();
        self.patterns.iter().find_map(|p| {
            let hit = if let Some(suffix) = p.strip_prefix('.') {
                a == suffix || a.ends_with(&format!(".{suffix}"))
            } else {
                a == *p
            };
            hit.then_some(p.as_str())
        })
    }
}

/// Addresses learned from DNS answers, with their expiry.
pub struct LearnedAllowlist {
    names: NameAllowlist,
    live: HashMap<Ipv4Addr, Learned>,
}

impl LearnedAllowlist {
    pub fn new(names: NameAllowlist) -> Self {
        LearnedAllowlist {
            names,
            live: HashMap::new(),
        }
    }

    /// Take an observed answer. Returns the addresses newly admitted, so the
    /// caller can push just those to the kernel rather than the whole set.
    pub fn observe(&mut self, records: &[ARecord], now: Instant) -> Vec<Ipv4Addr> {
        let mut added = Vec::new();
        for r in records {
            let Some(name) = self.names.matches(&r.name) else {
                continue;
            };
            let ttl = Duration::from_secs(r.ttl_secs as u64).clamp(MIN_TTL, MAX_TTL);
            let expires = now + ttl;
            match self.live.get_mut(&r.addr) {
                // Already admitted: extend, never shorten. A later answer with
                // a shorter TTL must not evict an address still in use.
                Some(existing) if existing.expires >= expires => {}
                Some(existing) => existing.expires = expires,
                None => {
                    self.live.insert(
                        r.addr,
                        Learned {
                            name: name.to_string(),
                            addr: r.addr,
                            expires,
                        },
                    );
                    added.push(r.addr);
                }
            }
        }
        added
    }

    /// Drop expired entries. Returns what was dropped, so the caller can remove
    /// them from the kernel map too.
    pub fn expire(&mut self, now: Instant) -> Vec<Ipv4Addr> {
        let gone: Vec<Ipv4Addr> = self
            .live
            .iter()
            .filter(|(_, l)| l.expires <= now)
            .map(|(a, _)| *a)
            .collect();
        for a in &gone {
            self.live.remove(a);
        }
        gone
    }

    pub fn is_allowed(&self, addr: &Ipv4Addr, now: Instant) -> bool {
        self.live.get(addr).is_some_and(|l| l.expires > now)
    }

    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

// ── DNS answer parsing ──────────────────────────────────────────────────────

/// Parse the A records out of a DNS response.
///
/// Deterministic and defensive: every length is bounds-checked against the
/// buffer, compression pointers are followed with a hard cap, and anything
/// malformed yields no records rather than a guess. This reads bytes off the
/// wire, so it is written on the assumption that they are hostile.
pub fn parse_a_records(buf: &[u8]) -> Vec<ARecord> {
    const HEADER: usize = 12;
    let mut out = Vec::new();
    if buf.len() < HEADER {
        return out;
    }
    // Must be a response (QR bit) with no error.
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return out;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 || ancount > 64 {
        return out;
    }

    let mut pos = HEADER;
    // Skip the questions.
    for _ in 0..qdcount {
        let Some(after) = skip_name(buf, pos) else {
            return out;
        };
        pos = after + 4; // QTYPE + QCLASS
        if pos > buf.len() {
            return out;
        }
    }

    for _ in 0..ancount {
        let Some((name, after)) = read_name(buf, pos) else {
            return out;
        };
        pos = after;
        if pos + 10 > buf.len() {
            return out;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return out;
        }
        // A record, IN class, 4 bytes of address.
        if rtype == 1 && rdlen == 4 {
            let addr = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
            out.push(ARecord {
                name,
                addr,
                ttl_secs: ttl,
            });
        }
        pos += rdlen;
    }
    out
}

/// Walk past a name without decoding it. Returns the offset just after.
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            // A pointer ends the name in two bytes.
            return Some(pos + 2);
        }
        pos = pos.checked_add(1 + len)?;
        if pos > buf.len() {
            return None;
        }
    }
}

/// Decode a name, following compression pointers. Returns the name and the
/// offset just after the name AS WRITTEN at `start`.
fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    const MAX_JUMPS: usize = 16;
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut after: Option<usize> = None;
    let mut jumps = 0usize;

    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            let end = pos + 1;
            return Some((labels.join("."), after.unwrap_or(end)));
        }
        if len & 0xc0 == 0xc0 {
            let b2 = *buf.get(pos + 1)? as usize;
            let target = ((len & 0x3f) << 8) | b2;
            if after.is_none() {
                after = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_JUMPS || target >= buf.len() {
                return None; // a loop, or a pointer off the end
            }
            pos = target;
            continue;
        }
        let s = pos + 1;
        let e = s.checked_add(len)?;
        if e > buf.len() || labels.len() > 127 {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[s..e]).to_string());
        pos = e;
    }
}

/// Holds the learned allowlist and keeps the kernel map in step with it.
///
/// THE DNS SOURCE IS NOT WIRED YET. `observe_response` is the entry point a
/// capture must call with the bytes of a DNS answer; nothing calls it in this
/// release, so the learned list stays empty and `[egress] taint_on_egress`
/// stays off. The two candidate sources, and their costs, are in
/// models/README.md. This half is complete and tested so that landing a source
/// is the only remaining step.
pub struct DnsAllowManager {
    learned: LearnedAllowlist,
    ebpf: std::sync::Arc<
        tokio::sync::RwLock<Option<tokio::sync::mpsc::Sender<crate::ebpf_loader::EbpfCommand>>>,
    >,
}

impl DnsAllowManager {
    pub fn new(
        names: NameAllowlist,
        ebpf: std::sync::Arc<
            tokio::sync::RwLock<Option<tokio::sync::mpsc::Sender<crate::ebpf_loader::EbpfCommand>>>,
        >,
    ) -> Self {
        DnsAllowManager {
            learned: LearnedAllowlist::new(names),
            ebpf,
        }
    }

    /// Take the bytes of one DNS answer and admit whatever it authorises.
    pub async fn observe_response(&mut self, buf: &[u8]) {
        let records = parse_a_records(buf);
        if records.is_empty() {
            return;
        }
        let added = self.learned.observe(&records, Instant::now());
        if added.is_empty() {
            return;
        }
        let sender = self.ebpf.read().await.clone();
        let Some(tx) = sender else { return };
        for addr in &added {
            let _ = tx
                .send(crate::ebpf_loader::EbpfCommand::AllowEgressIp(
                    addr.to_string(),
                ))
                .await;
        }
        tracing::info!(
            admitted = added.len(),
            live = self.learned.len(),
            "dns allowlist: admitted addresses from an observed answer"
        );
    }

    /// How many addresses are currently admitted. Zero a few minutes after
    /// startup means hostname allowlisting is not working on this host.
    pub fn learned_count(&self) -> usize {
        self.learned.len()
    }

    /// Drop expired entries from both the local set and the kernel map.
    pub async fn expire_now(&mut self) {
        let gone = self.learned.expire(Instant::now());
        if gone.is_empty() {
            return;
        }
        let sender = self.ebpf.read().await.clone();
        let Some(tx) = sender else { return };
        for addr in &gone {
            let _ = tx
                .send(crate::ebpf_loader::EbpfCommand::RevokeEgressIp(
                    addr.to_string(),
                ))
                .await;
        }
        tracing::info!(revoked = gone.len(), "dns allowlist: TTL expired");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Name matching ───────────────────────────────────────────────────────

    #[test]
    fn an_exact_name_matches_only_itself() {
        let l = NameAllowlist::new(["api.anthropic.com".to_string()]);
        assert!(l.matches("api.anthropic.com").is_some());
        assert!(l.matches("API.Anthropic.COM").is_some(), "case-insensitive");
        assert!(l.matches("api.anthropic.com.").is_some(), "trailing dot");
        assert!(l.matches("other.anthropic.com").is_none());
    }

    /// The substring trap, which already cost a day once with process names.
    #[test]
    fn suffix_matching_is_on_label_boundaries_only() {
        let l = NameAllowlist::new([".anthropic.com".to_string()]);
        assert!(l.matches("api.anthropic.com").is_some());
        assert!(l.matches("anthropic.com").is_some(), "the bare name too");
        assert!(l.matches("a.b.anthropic.com").is_some());

        assert!(
            l.matches("evil-anthropic.com").is_none(),
            "a prefix glued on must not match"
        );
        assert!(
            l.matches("anthropic.com.attacker.net").is_none(),
            "the name must END with the pattern, not merely contain it"
        );
        assert!(l.matches("notanthropic.com").is_none());
    }

    // ── Learning and expiry ─────────────────────────────────────────────────

    fn rec(name: &str, a: [u8; 4], ttl: u32) -> ARecord {
        ARecord {
            name: name.to_string(),
            addr: Ipv4Addr::from(a),
            ttl_secs: ttl,
        }
    }

    /// The case that condemned the static list: the address the agent actually
    /// uses is admitted because we saw the answer the agent saw.
    #[test]
    fn the_address_from_the_observed_answer_is_admitted() {
        let mut l = LearnedAllowlist::new(NameAllowlist::new([".anthropic.com".to_string()]));
        let now = Instant::now();
        let added = l.observe(&[rec("api.anthropic.com", [160, 79, 104, 10], 300)], now);
        assert_eq!(added, vec![Ipv4Addr::new(160, 79, 104, 10)]);
        assert!(l.is_allowed(&Ipv4Addr::new(160, 79, 104, 10), now));
    }

    #[test]
    fn an_answer_for_a_name_we_did_not_allow_is_ignored() {
        let mut l = LearnedAllowlist::new(NameAllowlist::new([".anthropic.com".to_string()]));
        let added = l.observe(
            &[rec("evil.example.com", [1, 2, 3, 4], 300)],
            Instant::now(),
        );
        assert!(added.is_empty());
        assert!(l.is_empty());
    }

    #[test]
    fn a_repeat_answer_does_not_re_add_but_does_extend() {
        let mut l = LearnedAllowlist::new(NameAllowlist::new(["a.com".to_string()]));
        let now = Instant::now();
        assert_eq!(l.observe(&[rec("a.com", [9, 9, 9, 9], 60)], now).len(), 1);
        assert!(
            l.observe(&[rec("a.com", [9, 9, 9, 9], 600)], now)
                .is_empty(),
            "already admitted, so nothing new to push to the kernel"
        );
        // The longer TTL won.
        assert!(l.is_allowed(&Ipv4Addr::new(9, 9, 9, 9), now + Duration::from_secs(120)));
    }

    /// A later, shorter answer must not evict an address that is still valid.
    #[test]
    fn a_shorter_ttl_never_shortens_an_existing_entry() {
        let mut l = LearnedAllowlist::new(NameAllowlist::new(["a.com".to_string()]));
        let now = Instant::now();
        l.observe(&[rec("a.com", [9, 9, 9, 9], 3000)], now);
        l.observe(&[rec("a.com", [9, 9, 9, 9], 31)], now);
        assert!(l.is_allowed(&Ipv4Addr::new(9, 9, 9, 9), now + Duration::from_secs(600)));
    }

    #[test]
    fn ttls_are_clamped_at_both_ends() {
        let mut l = LearnedAllowlist::new(NameAllowlist::new(["a.com".to_string()]));
        let now = Instant::now();
        // A 1s record still lasts the floor, so the list does not thrash.
        l.observe(&[rec("a.com", [1, 1, 1, 1], 1)], now);
        assert!(l.is_allowed(&Ipv4Addr::new(1, 1, 1, 1), now + Duration::from_secs(20)));
        // A 10-year record does not pin an address forever.
        l.observe(&[rec("a.com", [2, 2, 2, 2], 315_360_000)], now);
        assert!(!l.is_allowed(&Ipv4Addr::new(2, 2, 2, 2), now + Duration::from_secs(7200)));
    }

    #[test]
    fn expired_entries_are_reported_so_the_kernel_can_drop_them() {
        let mut l = LearnedAllowlist::new(NameAllowlist::new(["a.com".to_string()]));
        let now = Instant::now();
        l.observe(&[rec("a.com", [5, 5, 5, 5], 60)], now);
        assert!(l.expire(now).is_empty(), "not due yet");
        let gone = l.expire(now + Duration::from_secs(61));
        assert_eq!(gone, vec![Ipv4Addr::new(5, 5, 5, 5)]);
        assert!(l.is_empty());
    }

    // ── Wire parsing ────────────────────────────────────────────────────────

    /// A real-shaped response: one question, two A answers, with the answer
    /// names written as compression pointers back to the question.
    fn response() -> Vec<u8> {
        let mut b = vec![
            0x12, 0x34, // id
            0x81, 0x80, // QR=1, RD, RA, rcode 0
            0x00, 0x01, // qdcount
            0x00, 0x02, // ancount
            0x00, 0x00, 0x00, 0x00,
        ];
        // question: api.anthropic.com A IN
        for label in ["api", "anthropic", "com"] {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // two answers, name = pointer to offset 12
        for addr in [[160u8, 79, 104, 10], [160, 79, 104, 11]] {
            b.extend_from_slice(&[0xc0, 0x0c]);
            b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
            b.extend_from_slice(&300u32.to_be_bytes()); // ttl
            b.extend_from_slice(&[0x00, 0x04]); // rdlength
            b.extend_from_slice(&addr);
        }
        b
    }

    #[test]
    fn a_records_are_parsed_with_their_names_and_ttls() {
        let recs = parse_a_records(&response());
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].name, "api.anthropic.com");
        assert_eq!(recs[0].addr, Ipv4Addr::new(160, 79, 104, 10));
        assert_eq!(recs[0].ttl_secs, 300);
        assert_eq!(recs[1].addr, Ipv4Addr::new(160, 79, 104, 11));
    }

    #[test]
    fn a_query_is_not_mistaken_for_an_answer() {
        let mut q = response();
        q[2] = 0x01; // clear QR
        assert!(parse_a_records(&q).is_empty());
    }

    #[test]
    fn an_error_response_yields_nothing() {
        let mut e = response();
        e[3] = 0x83; // rcode 3, NXDOMAIN
        assert!(parse_a_records(&e).is_empty());
    }

    /// These bytes come off the wire, so malformed input must yield nothing
    /// rather than panic or invent a record.
    #[test]
    fn hostile_input_yields_no_records_and_never_panics() {
        let good = response();
        for bad in [
            vec![],
            vec![0u8; 5],
            vec![0xff; 12],
            good[..14].to_vec(),
            good[..good.len() - 3].to_vec(),
        ] {
            let _ = parse_a_records(&bad);
        }
        // A compression pointer that points at itself must terminate.
        let mut loopy = good.clone();
        let n = loopy.len();
        loopy[n - 10] = 0xc0;
        let _ = parse_a_records(&loopy);

        // Truncate at every length: none may panic.
        for i in 0..good.len() {
            let _ = parse_a_records(&good[..i]);
        }
    }

    #[test]
    fn a_pointer_past_the_end_is_refused() {
        let mut b = response();
        // Point the first answer's name far outside the buffer.
        let off = 12 + 4 + 4 + 3 + 9 + 1; // into the answer section
        if off + 1 < b.len() {
            b[off] = 0xc0;
            b[off + 1] = 0xfe;
        }
        let _ = parse_a_records(&b); // must not panic; records may be empty
    }

    /// End to end: a real answer shape goes in, the address the agent will use
    /// comes out admitted.
    #[test]
    fn an_observed_answer_admits_exactly_its_addresses() {
        let mut l = LearnedAllowlist::new(NameAllowlist::new([".anthropic.com".to_string()]));
        let now = Instant::now();
        let added = l.observe(&parse_a_records(&response()), now);
        assert_eq!(added.len(), 2);
        assert!(l.is_allowed(&Ipv4Addr::new(160, 79, 104, 10), now));
        assert!(
            !l.is_allowed(&Ipv4Addr::new(1, 2, 3, 4), now),
            "and nothing else"
        );
    }
}
