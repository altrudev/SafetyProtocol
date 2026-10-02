use safetyprotocol::*;

fn public_candidate() -> NetworkCandidate {
    NetworkCandidate {
        user_approved: false,
        known_identity: false,
        open_network: true,
        captive_portal: false,
        fingerprint_matches: false,
        contradictory_evidence: false,
        hard_drift: false,
        protected_tunnel_ready: true,
        estimated_cost_microunits_per_mb: 0,
    }
}

#[test]
fn ssid_like_familiarity_cannot_create_trust() {
    let mut c = public_candidate();
    c.fingerprint_matches = true;
    let d = evaluate(&c, &Policy::default());
    assert_ne!(d.authority, ConnectivityAuthority::Trusted);
}

#[test]
fn protected_public_requires_tunnel() {
    let mut c = public_candidate();
    c.protected_tunnel_ready = false;
    let d = evaluate(&c, &Policy::default());
    assert_eq!(d.authority, ConnectivityAuthority::Denied);
    assert_eq!(d.reason, DecisionReason::ProtectedTransportUnavailable);
}

#[test]
fn verified_user_approved_network_can_be_trusted() {
    let mut c = public_candidate();
    c.user_approved = true;
    c.known_identity = true;
    c.open_network = false;
    c.fingerprint_matches = true;
    let d = evaluate(&c, &Policy::default());
    assert_eq!(d.authority, ConnectivityAuthority::Trusted);
}

#[test]
fn contradictory_evidence_demotes_previously_acceptable_network() {
    let mut c = public_candidate();
    c.user_approved = true;
    c.known_identity = true;
    c.open_network = false;
    c.fingerprint_matches = true;
    c.contradictory_evidence = true;
    let d = evaluate(&c, &Policy::default());
    assert_ne!(d.authority, ConnectivityAuthority::Trusted);
}

#[test]
fn unknown_is_not_trusted() {
    let c = NetworkCandidate::default();
    let d = evaluate(&c, &Policy::default());
    assert_ne!(d.authority, ConnectivityAuthority::Trusted);
}

#[test]
fn hard_cellular_budget_blocks_over_budget_fallback() {
    let c = NetworkCandidate {
        estimated_cost_microunits_per_mb: 100,
        ..NetworkCandidate::default()
    };
    let p = Policy {
        allow_cellular_fallback: true,
        remaining_cellular_budget_mb: 0,
    };
    let d = evaluate(&c, &p);
    assert_eq!(d.authority, ConnectivityAuthority::Denied);
    assert_eq!(d.reason, DecisionReason::CellularBudgetExhausted);
}

#[test]
fn hard_drift_denies_even_previously_trusted_network() {
    let mut c = public_candidate();
    c.user_approved = true;
    c.known_identity = true;
    c.open_network = false;
    c.fingerprint_matches = true;
    c.hard_drift = true;
    let d = evaluate(&c, &Policy::default());
    assert_eq!(d.authority, ConnectivityAuthority::Denied);
    assert_eq!(d.reason, DecisionReason::HardDrift);
}

#[test]
fn protected_public_has_no_local_network_or_direct_dns_authority() {
    let c = public_candidate();
    let d = evaluate(&c, &Policy::default());
    assert_eq!(d.authority, ConnectivityAuthority::ProtectedTransport);
    assert!(d.effective.transport);
    assert!(!d.effective.local_network);
    assert!(!d.effective.direct_dns);
    assert!(d.protected_tunnel_required);
}
