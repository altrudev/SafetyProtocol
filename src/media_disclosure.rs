//! Synthetic-media disclosure safety primitive.
//!
//! The core invariant is that model/rendering artifacts are never evidence of disclosure.
//! Human-visible disclosure and machine-verifiable provenance are explicit, independent
//! channels with their own freshness/availability requirements.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RenderQuality {
    #[default]
    Unknown,
    Stable,
    Degraded,
    Unstable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticMediaDisclosurePolicy {
    /// Require a persistent human-visible synthetic-media indicator.
    pub require_visual_indicator: bool,
    /// Require a spoken disclosure at session start and after the configured refresh window.
    pub require_spoken_disclosure: bool,
    /// Maximum age of the last confirmed spoken disclosure.
    ///
    /// A value of 0 means every evaluation requires a fresh spoken disclosure.
    pub spoken_disclosure_max_age_ms: u64,
    /// Require an independently attested watermark/provenance channel.
    pub require_watermark_attestation: bool,
}

impl Default for SyntheticMediaDisclosurePolicy {
    fn default() -> Self {
        Self {
            require_visual_indicator: true,
            require_spoken_disclosure: true,
            spoken_disclosure_max_age_ms: 5 * 60 * 1000,
            require_watermark_attestation: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticMediaDisclosureEvidence {
    /// Explicit user-visible marker controlled outside the generative renderer.
    pub visual_indicator_present: bool,
    /// Age of the last independently confirmed spoken disclosure.
    pub spoken_disclosure_age_ms: Option<u64>,
    /// Evidence that the configured watermark/provenance mechanism was applied.
    pub watermark_attested: bool,
    /// Diagnostic only. Never contributes to disclosure authority.
    pub render_quality: RenderQuality,
}

impl Default for SyntheticMediaDisclosureEvidence {
    fn default() -> Self {
        Self {
            visual_indicator_present: false,
            spoken_disclosure_age_ms: None,
            watermark_attested: false,
            render_quality: RenderQuality::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntheticMediaDisclosureReason {
    ExplicitDisclosureSatisfied,
    VisualIndicatorMissing,
    SpokenDisclosureMissing,
    SpokenDisclosureStale,
    WatermarkAttestationMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticMediaDisclosureDecision {
    /// True only when every disclosure channel required by policy is independently satisfied.
    pub humanlike_presentation_permitted: bool,
    /// True when the caller must present a non-generative fallback disclosure or stop
    /// humanlike presentation before continuing.
    pub fallback_disclosure_required: bool,
    pub reason: SyntheticMediaDisclosureReason,
}

pub fn evaluate_synthetic_media_disclosure(
    policy: &SyntheticMediaDisclosurePolicy,
    evidence: &SyntheticMediaDisclosureEvidence,
) -> SyntheticMediaDisclosureDecision {
    // Render quality is intentionally not consulted. Visual glitches, identity drift,
    // frame instability, or other generator artifacts are not a disclosure mechanism.
    let _diagnostic_render_quality = evidence.render_quality;

    if policy.require_visual_indicator && !evidence.visual_indicator_present {
        return SyntheticMediaDisclosureDecision {
            humanlike_presentation_permitted: false,
            fallback_disclosure_required: true,
            reason: SyntheticMediaDisclosureReason::VisualIndicatorMissing,
        };
    }

    if policy.require_spoken_disclosure {
        let Some(age_ms) = evidence.spoken_disclosure_age_ms else {
            return SyntheticMediaDisclosureDecision {
                humanlike_presentation_permitted: false,
                fallback_disclosure_required: true,
                reason: SyntheticMediaDisclosureReason::SpokenDisclosureMissing,
            };
        };

        if age_ms > policy.spoken_disclosure_max_age_ms {
            return SyntheticMediaDisclosureDecision {
                humanlike_presentation_permitted: false,
                fallback_disclosure_required: true,
                reason: SyntheticMediaDisclosureReason::SpokenDisclosureStale,
            };
        }
    }

    if policy.require_watermark_attestation && !evidence.watermark_attested {
        return SyntheticMediaDisclosureDecision {
            humanlike_presentation_permitted: false,
            fallback_disclosure_required: true,
            reason: SyntheticMediaDisclosureReason::WatermarkAttestationMissing,
        };
    }

    SyntheticMediaDisclosureDecision {
        humanlike_presentation_permitted: true,
        fallback_disclosure_required: false,
        reason: SyntheticMediaDisclosureReason::ExplicitDisclosureSatisfied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_evidence(render_quality: RenderQuality) -> SyntheticMediaDisclosureEvidence {
        SyntheticMediaDisclosureEvidence {
            visual_indicator_present: true,
            spoken_disclosure_age_ms: Some(1_000),
            watermark_attested: true,
            render_quality,
        }
    }

    #[test]
    fn complete_explicit_disclosure_allows_humanlike_presentation() {
        let decision = evaluate_synthetic_media_disclosure(
            &SyntheticMediaDisclosurePolicy::default(),
            &complete_evidence(RenderQuality::Stable),
        );

        assert!(decision.humanlike_presentation_permitted);
        assert!(!decision.fallback_disclosure_required);
        assert_eq!(
            decision.reason,
            SyntheticMediaDisclosureReason::ExplicitDisclosureSatisfied
        );
    }

    #[test]
    fn render_instability_never_substitutes_for_disclosure() {
        let evidence = SyntheticMediaDisclosureEvidence {
            visual_indicator_present: false,
            spoken_disclosure_age_ms: None,
            watermark_attested: false,
            render_quality: RenderQuality::Unstable,
        };

        let decision = evaluate_synthetic_media_disclosure(
            &SyntheticMediaDisclosurePolicy::default(),
            &evidence,
        );

        assert!(!decision.humanlike_presentation_permitted);
        assert!(decision.fallback_disclosure_required);
        assert_eq!(
            decision.reason,
            SyntheticMediaDisclosureReason::VisualIndicatorMissing
        );
    }

    #[test]
    fn stale_spoken_disclosure_requires_refresh() {
        let policy = SyntheticMediaDisclosurePolicy {
            spoken_disclosure_max_age_ms: 10_000,
            ..SyntheticMediaDisclosurePolicy::default()
        };
        let evidence = SyntheticMediaDisclosureEvidence {
            spoken_disclosure_age_ms: Some(10_001),
            ..complete_evidence(RenderQuality::Stable)
        };

        let decision = evaluate_synthetic_media_disclosure(&policy, &evidence);

        assert_eq!(
            decision.reason,
            SyntheticMediaDisclosureReason::SpokenDisclosureStale
        );
        assert!(!decision.humanlike_presentation_permitted);
    }

    #[test]
    fn watermark_does_not_replace_human_visible_disclosure() {
        let evidence = SyntheticMediaDisclosureEvidence {
            visual_indicator_present: false,
            spoken_disclosure_age_ms: Some(0),
            watermark_attested: true,
            render_quality: RenderQuality::Stable,
        };

        let decision = evaluate_synthetic_media_disclosure(
            &SyntheticMediaDisclosurePolicy::default(),
            &evidence,
        );

        assert_eq!(
            decision.reason,
            SyntheticMediaDisclosureReason::VisualIndicatorMissing
        );
    }

    #[test]
    fn visible_and_spoken_channels_can_be_required_without_watermark() {
        let policy = SyntheticMediaDisclosurePolicy {
            require_watermark_attestation: false,
            ..SyntheticMediaDisclosurePolicy::default()
        };
        let evidence = SyntheticMediaDisclosureEvidence {
            visual_indicator_present: true,
            spoken_disclosure_age_ms: Some(500),
            watermark_attested: false,
            render_quality: RenderQuality::Degraded,
        };

        let decision = evaluate_synthetic_media_disclosure(&policy, &evidence);

        assert!(decision.humanlike_presentation_permitted);
        assert_eq!(
            decision.reason,
            SyntheticMediaDisclosureReason::ExplicitDisclosureSatisfied
        );
    }

    #[test]
    fn render_quality_never_changes_an_otherwise_identical_decision() {
        let policy = SyntheticMediaDisclosurePolicy::default();

        let stable = evaluate_synthetic_media_disclosure(
            &policy,
            &complete_evidence(RenderQuality::Stable),
        );
        let unstable = evaluate_synthetic_media_disclosure(
            &policy,
            &complete_evidence(RenderQuality::Unstable),
        );

        assert_eq!(stable, unstable);
    }
}
