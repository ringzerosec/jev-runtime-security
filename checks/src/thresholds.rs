// SPDX-License-Identifier: Apache-2.0
//
// thresholds.rs — the numbers this layer judges by, in one place.
//
// These used to be literals scattered through lib.rs and jev.rs. An operator
// who thought a band was in the wrong place had no way to say so short of
// editing the source, and nobody reading the config could tell what the layer
// would do. They are now configuration, with these values as the defaults, and
// they are validated at load rather than clamped quietly: a nonsensical set is
// an operator error worth stopping for, not something to paper over.
//
// Nothing here is in a syscall path. These numbers decide what gets labelled
// and what gets queued for a human, never what the kernel allows.

use serde::{Deserialize, Serialize};

/// What the deterministic scorer says when a rule of a given strength fires.
///
/// `probability` is the weight given to the chosen option; `confidence` is how
/// strongly the evidence determined it. A remote provider may raise either,
/// never lower them.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Band {
    pub probability: f32,
    pub confidence: f32,
}

impl Band {
    pub const fn new(probability: f32, confidence: f32) -> Self {
        Band {
            probability,
            confidence,
        }
    }
}

/// Every tunable number in the checks layer.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// At or above this, a probability from the model means the layer calls it
    /// a matched secret rather than a possible one. Raising it makes the layer
    /// say "definitely" less often.
    pub secret_pattern_matched_at: f32,
    /// At or above this, a probability means "possible secret". Below it, the
    /// layer says nothing. Lowering it produces more flags and more noise.
    pub possible_secret_at: f32,

    /// A literal pattern matched with no interpretation: a secret regex hit the
    /// text exactly. The most certain thing this layer ever says.
    pub secret_pattern: Band,
    /// An unambiguous hit: a credential path named in a tool call's arguments.
    pub strong_match: Band,
    /// A rule fired, but the case is judgeable either way: a write outside the
    /// stated workspace, for instance.
    pub partial_match: Band,
    /// A hint rather than a finding: an unapproved host when no approved list
    /// was configured.
    pub weak_match: Band,
    /// What the scorer says when nothing fired.
    pub benign: Band,

    /// A non-benign result at or above this probability is worth a human's
    /// time, and is put in the review queue. Raising it means fewer items to
    /// label and more missed. It does not change what is enforced.
    pub flag_at: f32,
}

impl Default for Thresholds {
    fn default() -> Self {
        // These are the values the layer shipped with as literals. Changing a
        // default changes behaviour for everyone who has not set it, so they
        // stay put unless there is a measured reason.
        Thresholds {
            secret_pattern_matched_at: 0.85,
            possible_secret_at: 0.40,
            secret_pattern: Band::new(0.95, 0.90),
            strong_match: Band::new(0.90, 0.90),
            partial_match: Band::new(0.70, 0.80),
            weak_match: Band::new(0.50, 0.40),
            benign: Band::new(0.90, 0.60),
            flag_at: 0.40,
        }
    }
}

impl Thresholds {
    /// Refuse a set that cannot mean anything sensible.
    ///
    /// Returns every problem, not just the first, so an operator fixing a
    /// config does not have to discover them one restart at a time.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();

        let mut in_range = |name: &str, v: f32| {
            if !v.is_finite() || !(0.0..=1.0).contains(&v) {
                errs.push(format!(
                    "[checks.thresholds] {name} = {v} is not a probability; it must be between \
                     0.0 and 1.0"
                ));
            }
        };
        in_range("secret_pattern_matched_at", self.secret_pattern_matched_at);
        in_range("possible_secret_at", self.possible_secret_at);
        in_range("flag_at", self.flag_at);
        for (name, band) in [
            ("secret_pattern", self.secret_pattern),
            ("strong_match", self.strong_match),
            ("partial_match", self.partial_match),
            ("weak_match", self.weak_match),
            ("benign", self.benign),
        ] {
            in_range(&format!("{name}.probability"), band.probability);
            in_range(&format!("{name}.confidence"), band.confidence);
        }
        drop(in_range);

        if self.secret_pattern_matched_at < self.possible_secret_at {
            errs.push(format!(
                "[checks.thresholds] secret_pattern_matched_at ({}) is below possible_secret_at \
                 ({}). The stronger band cannot sit below the weaker one, or nothing would ever \
                 be called a possible secret",
                self.secret_pattern_matched_at, self.possible_secret_at
            ));
        }
        if self.secret_pattern.probability < self.strong_match.probability {
            errs.push(format!(
                "[checks.thresholds] secret_pattern.probability ({}) is below \
                 strong_match.probability ({}). An exact pattern match cannot score lower than \
                 an inferred one",
                self.secret_pattern.probability, self.strong_match.probability
            ));
        }
        if self.strong_match.probability < self.partial_match.probability {
            errs.push(format!(
                "[checks.thresholds] strong_match.probability ({}) is below \
                 partial_match.probability ({}). A stronger rule cannot score lower than a \
                 weaker one",
                self.strong_match.probability, self.partial_match.probability
            ));
        }
        if self.partial_match.probability < self.weak_match.probability {
            errs.push(format!(
                "[checks.thresholds] partial_match.probability ({}) is below \
                 weak_match.probability ({}). A stronger rule cannot score lower than a weaker \
                 one",
                self.partial_match.probability, self.weak_match.probability
            ));
        }
        if self.flag_at > self.weak_match.probability {
            errs.push(format!(
                "[checks.thresholds] flag_at ({}) is above weak_match.probability ({}), so a \
                 weak match could never reach the review queue. Lower flag_at, or raise the weak \
                 band",
                self.flag_at, self.weak_match.probability
            ));
        }

        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    /// Which band a probability falls in, for the `noul` answer that comes back
    /// as a bare number.
    pub fn exposure_option(&self, noul: f32) -> &'static str {
        if noul >= self.secret_pattern_matched_at {
            "secret_pattern_matched"
        } else if noul >= self.possible_secret_at {
            "possible_secret"
        } else {
            "none"
        }
    }

    /// Is this result worth a human's time?
    pub fn worth_queueing(&self, option: &str, probability: f32) -> bool {
        !matches!(option, "benign" | "none") && probability >= self.flag_at
    }
}

/// The set this process scores with.
///
/// Written once, at startup, after validation. A process-wide value rather than
/// a parameter on every scorer: these are configuration, identical for every
/// call in the process, and threading them through the deterministic scorers,
/// the provider and its transport would add a parameter to every signature
/// without making anything more correct. Nothing mutates it after startup, so
/// there is no interleaving to reason about.
static CONFIGURED: std::sync::OnceLock<Thresholds> = std::sync::OnceLock::new();

/// Install the operator's thresholds. Call once, early, with a validated set.
///
/// Returns `Err` with the set already installed if called twice, so a second
/// caller cannot silently believe it changed anything.
pub fn install(t: Thresholds) -> Result<(), Thresholds> {
    CONFIGURED.set(t)
}

/// The thresholds in force. The defaults until `install` has been called, which
/// is what the unit tests and any library user gets.
pub fn current() -> Thresholds {
    *CONFIGURED.get().unwrap_or(&DEFAULTS)
}

static DEFAULTS: Thresholds = Thresholds {
    secret_pattern_matched_at: 0.85,
    possible_secret_at: 0.40,
    secret_pattern: Band::new(0.95, 0.90),
    strong_match: Band::new(0.90, 0.90),
    partial_match: Band::new(0.70, 0.80),
    weak_match: Band::new(0.50, 0.40),
    benign: Band::new(0.90, 0.60),
    flag_at: 0.40,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The const used by `current()` and the `Default` impl must not drift.
    #[test]
    fn the_static_defaults_match_the_default_impl() {
        assert_eq!(DEFAULTS, Thresholds::default());
    }

    #[test]
    fn the_defaults_are_the_values_the_layer_shipped_with() {
        let t = Thresholds::default();
        assert_eq!(t.secret_pattern_matched_at, 0.85);
        assert_eq!(t.possible_secret_at, 0.40);
        assert_eq!(t.secret_pattern, Band::new(0.95, 0.90));
        assert_eq!(t.strong_match, Band::new(0.90, 0.90));
        assert_eq!(t.partial_match, Band::new(0.70, 0.80));
        assert_eq!(t.weak_match, Band::new(0.50, 0.40));
        assert_eq!(t.benign, Band::new(0.90, 0.60));
        t.validate().expect("the defaults must be valid");
    }

    #[test]
    fn a_probability_outside_zero_to_one_is_refused() {
        let mut t = Thresholds::default();
        t.possible_secret_at = 1.5;
        let errs = t.validate().expect_err("must refuse");
        assert!(
            errs.iter().any(|e| e.contains("possible_secret_at")),
            "{errs:?}"
        );
        assert!(
            errs.iter().any(|e| e.contains("between 0.0 and 1.0")),
            "{errs:?}"
        );
    }

    #[test]
    fn a_nan_is_refused_rather_than_compared() {
        let mut t = Thresholds::default();
        t.flag_at = f32::NAN;
        assert!(t.validate().is_err());
    }

    /// The ordering rule: a stronger band may not sit below a weaker one.
    #[test]
    fn bands_out_of_order_are_refused_with_a_reason() {
        let mut t = Thresholds::default();
        t.secret_pattern_matched_at = 0.2;
        t.possible_secret_at = 0.6;
        let errs = t.validate().expect_err("must refuse");
        assert!(
            errs.iter().any(|e| e.contains("cannot sit below")),
            "the error must say why: {errs:?}"
        );

        let mut t = Thresholds::default();
        t.strong_match = Band::new(0.3, 0.9);
        let errs = t.validate().expect_err("must refuse");
        assert!(
            errs.iter().any(|e| e.contains("strong_match.probability")),
            "{errs:?}"
        );

        // An exact match may not rank below an inferred one either.
        let mut t = Thresholds::default();
        t.secret_pattern = Band::new(0.5, 0.9);
        let errs = t.validate().expect_err("must refuse");
        assert!(
            errs.iter()
                .any(|e| e.contains("secret_pattern.probability")),
            "{errs:?}"
        );
    }

    /// A flag cut-off above the weakest band would silently mean "never queue
    /// a weak match", which is the kind of surprise this refuses.
    #[test]
    fn a_flag_cutoff_no_band_can_reach_is_refused() {
        let mut t = Thresholds::default();
        t.flag_at = 0.9;
        let errs = t.validate().expect_err("must refuse");
        assert!(
            errs.iter().any(|e| e.contains("could never reach")),
            "{errs:?}"
        );
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let mut t = Thresholds::default();
        t.possible_secret_at = 2.0;
        t.flag_at = -1.0;
        let errs = t.validate().expect_err("must refuse");
        assert!(errs.len() >= 2, "both problems must be named: {errs:?}");
    }

    #[test]
    fn the_exposure_bands_are_inclusive_at_the_bottom() {
        let t = Thresholds::default();
        assert_eq!(t.exposure_option(0.85), "secret_pattern_matched");
        assert_eq!(t.exposure_option(0.849), "possible_secret");
        assert_eq!(t.exposure_option(0.40), "possible_secret");
        assert_eq!(t.exposure_option(0.399), "none");
        assert_eq!(t.exposure_option(0.0), "none");
    }

    #[test]
    fn only_a_non_benign_result_above_the_cutoff_is_queued() {
        let t = Thresholds::default();
        assert!(!t.worth_queueing("benign", 1.0));
        assert!(!t.worth_queueing("none", 1.0));
        assert!(!t.worth_queueing("reads_sensitive_path", 0.1));
        assert!(t.worth_queueing("reads_sensitive_path", 0.4));
    }

    /// Changing a threshold must actually change where the bands fall.
    #[test]
    fn a_changed_threshold_moves_the_band() {
        let mut t = Thresholds::default();
        assert_eq!(t.exposure_option(0.5), "possible_secret");
        t.possible_secret_at = 0.6;
        assert_eq!(t.exposure_option(0.5), "none");
        t.validate().expect("still a valid set");
    }
}
