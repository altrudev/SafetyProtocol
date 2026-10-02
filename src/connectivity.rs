use crate::core::{Authority, DriftSeverity, Evidence, EvidenceLevel};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityAuthority {
    Trusted,
    ProtectedTransport,
    CellularFallback,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionReason {
    TrustedEvidenceSatisfied,
    ProtectedTransportOnly,
    ProtectedTransportUnavailable,
    ContradictoryEvidence,
    HardDrift,
    CellularFallbackAllowed,
    CellularBudgetExhausted,
    InsufficientEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkCandidate {
    pub user_approved: bool,
    pub known_identity: bool,
    pub open_network: bool,
    pub captive_portal: bool,
    pub fingerprint_matches: bool,
    pub contradictory_evidence: bool,
    pub hard_drift: bool,
    pub protected_tunnel_ready: bool,
    pub estimated_cost_microunits_per_mb: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Policy {
    pub allow_cellular_fallback: bool,
    pub remaining_cellular_budget_mb: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub authority: ConnectivityAuthority,
    pub reason: DecisionReason,
    pub effective: Authority,
    pub protected_tunnel_required: bool,
}

pub fn candidate_evidence(c: &NetworkCandidate) -> Evidence {
    Evidence {
        identity: if c.known_identity {
            EvidenceLevel::Authenticated
        } else if c.fingerprint_matches {
            EvidenceLevel::Observed
        } else {
            EvidenceLevel::Unknown
        },
        user_approved: c.user_approved,
        contradictory: c.contradictory_evidence,
        drift: if c.hard_drift {
            DriftSeverity::Hard
        } else {
            DriftSeverity::None
        },
        age_ms: 0,
        ttl_ms: 1,
    }
}

pub fn evaluate(c: &NetworkCandidate, p: &Policy) -> Decision {
    if c.contradictory_evidence {
        return denied(DecisionReason::ContradictoryEvidence);
    }
    if c.hard_drift {
        return denied(DecisionReason::HardDrift);
    }

    if c.user_approved
        && c.known_identity
        && !c.open_network
        && c.fingerprint_matches
        && !c.captive_portal
    {
        return Decision {
            authority: ConnectivityAuthority::Trusted,
            reason: DecisionReason::TrustedEvidenceSatisfied,
            effective: Authority {
                transport: true,
                local_network: true,
                direct_dns: true,
                data_egress: true,
                ..Authority::none()
            },
            protected_tunnel_required: false,
        };
    }

    if c.open_network || c.captive_portal || c.fingerprint_matches {
        if c.protected_tunnel_ready {
            return Decision {
                authority: ConnectivityAuthority::ProtectedTransport,
                reason: DecisionReason::ProtectedTransportOnly,
                effective: Authority {
                    transport: true,
                    data_egress: true,
                    ..Authority::none()
                },
                protected_tunnel_required: true,
            };
        }
        return denied(DecisionReason::ProtectedTransportUnavailable);
    }

    if p.allow_cellular_fallback && c.estimated_cost_microunits_per_mb > 0 {
        if p.remaining_cellular_budget_mb > 0 {
            return Decision {
                authority: ConnectivityAuthority::CellularFallback,
                reason: DecisionReason::CellularFallbackAllowed,
                effective: Authority {
                    transport: true,
                    direct_dns: true,
                    data_egress: true,
                    ..Authority::none()
                },
                protected_tunnel_required: false,
            };
        }
        return denied(DecisionReason::CellularBudgetExhausted);
    }

    denied(DecisionReason::InsufficientEvidence)
}

fn denied(reason: DecisionReason) -> Decision {
    Decision {
        authority: ConnectivityAuthority::Denied,
        reason,
        effective: Authority::none(),
        protected_tunnel_required: false,
    }
}
