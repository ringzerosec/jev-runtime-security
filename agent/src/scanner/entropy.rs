// SPDX-License-Identifier: Apache-2.0
// scanner/entropy.rs — Shannon entropy analysis for obfuscation detection

/// Compute Shannon entropy of a byte slice. Returns a value in [0.0, 8.0].
/// High entropy (>7.0) on source files → likely obfuscated, packed, or base64-encoded payload.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

/// Entropy thresholds.
pub const ENTROPY_SUSPICIOUS: f64 = 6.5; // worth flagging
pub const ENTROPY_HIGH: f64 = 7.0; // likely obfuscated

pub struct EntropyResult {
    pub score: f64,
    pub suspicious: bool,
    pub high: bool,
}

pub fn analyse(data: &[u8]) -> EntropyResult {
    let score = entropy(data);
    EntropyResult {
        score,
        suspicious: score >= ENTROPY_SUSPICIOUS,
        high: score >= ENTROPY_HIGH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_entropy_text() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(entropy(data) < 1.0);
    }

    #[test]
    fn high_entropy_random() {
        // Approximation using a known-high-entropy string (base64-like)
        let data = b"8J+YgDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6";
        assert!(entropy(data) > 4.0);
    }
}
