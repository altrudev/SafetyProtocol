use crate::connectivity::{
    ConnectivityAuthority, Decision, DecisionReason, NetworkCandidate, Policy, evaluate,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidTransport {
    None = 0,
    Wifi = 1,
    Cellular = 2,
    Ethernet = 3,
    Vpn = 4,
    Other = 5,
}

impl AndroidTransport {
    pub fn from_i32(value: i32) -> Self {
        match value {
            1 => Self::Wifi,
            2 => Self::Cellular,
            3 => Self::Ethernet,
            4 => Self::Vpn,
            5 => Self::Other,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AndroidConnectivityObservation {
    pub transport: AndroidTransport,
    pub validated_internet: bool,
    pub captive_portal: bool,
    pub protected_tunnel_ready: bool,
    pub contradictory_evidence: bool,
    pub hard_drift: bool,
    pub allow_cellular_fallback: bool,
    pub remaining_cellular_budget_mb: u64,
}

pub fn evaluate_android_connectivity(o: &AndroidConnectivityObservation) -> Decision {
    if o.contradictory_evidence {
        return evaluate(
            &NetworkCandidate {
                contradictory_evidence: true,
                ..NetworkCandidate::default()
            },
            &Policy::default(),
        );
    }
    if o.hard_drift {
        return evaluate(
            &NetworkCandidate {
                hard_drift: true,
                ..NetworkCandidate::default()
            },
            &Policy::default(),
        );
    }

    match o.transport {
        AndroidTransport::Wifi => {
            if !o.validated_internet || o.captive_portal {
                return denied_insufficient();
            }
            evaluate(
                &NetworkCandidate {
                    open_network: true,
                    captive_portal: false,
                    protected_tunnel_ready: o.protected_tunnel_ready,
                    ..NetworkCandidate::default()
                },
                &Policy::default(),
            )
        }
        AndroidTransport::Cellular => {
            if !o.validated_internet {
                return denied_insufficient();
            }
            evaluate(
                &NetworkCandidate {
                    estimated_cost_microunits_per_mb: 1,
                    ..NetworkCandidate::default()
                },
                &Policy {
                    allow_cellular_fallback: o.allow_cellular_fallback,
                    remaining_cellular_budget_mb: o.remaining_cellular_budget_mb,
                },
            )
        }
        AndroidTransport::None
        | AndroidTransport::Ethernet
        | AndroidTransport::Vpn
        | AndroidTransport::Other => denied_insufficient(),
    }
}

fn denied_insufficient() -> Decision {
    Decision {
        authority: ConnectivityAuthority::Denied,
        reason: DecisionReason::InsufficientEvidence,
        effective: crate::core::Authority::none(),
        protected_tunnel_required: false,
    }
}

pub const ANDROID_DECISION_ABI_VERSION: i32 = 1;

pub fn encode_android_decision(d: Decision) -> i64 {
    let authority = match d.authority {
        ConnectivityAuthority::Trusted => 0_i64,
        ConnectivityAuthority::ProtectedTransport => 1,
        ConnectivityAuthority::CellularFallback => 2,
        ConnectivityAuthority::Denied => 3,
    };
    let reason = match d.reason {
        DecisionReason::TrustedEvidenceSatisfied => 0_i64,
        DecisionReason::ProtectedTransportOnly => 1,
        DecisionReason::ProtectedTransportUnavailable => 2,
        DecisionReason::ContradictoryEvidence => 3,
        DecisionReason::HardDrift => 4,
        DecisionReason::CellularFallbackAllowed => 5,
        DecisionReason::CellularBudgetExhausted => 6,
        DecisionReason::InsufficientEvidence => 7,
    };

    let mut effective = 0_i64;
    if d.effective.transport {
        effective |= 1 << 0;
    }
    if d.effective.read {
        effective |= 1 << 1;
    }
    if d.effective.write {
        effective |= 1 << 2;
    }
    if d.effective.execute {
        effective |= 1 << 3;
    }
    if d.effective.local_network {
        effective |= 1 << 4;
    }
    if d.effective.direct_dns {
        effective |= 1 << 5;
    }
    if d.effective.credential_use {
        effective |= 1 << 6;
    }
    if d.effective.data_egress {
        effective |= 1 << 7;
    }

    authority | (reason << 8) | (effective << 16) | ((d.protected_tunnel_required as i64) << 24)
}
