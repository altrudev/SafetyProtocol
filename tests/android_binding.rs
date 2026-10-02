use safetyprotocol::{
    AndroidConnectivityObservation, AndroidTransport, ConnectivityAuthority, DecisionReason,
    encode_android_decision, evaluate_android_connectivity,
};

fn obs(transport: AndroidTransport) -> AndroidConnectivityObservation {
    AndroidConnectivityObservation {
        transport,
        validated_internet: true,
        captive_portal: false,
        protected_tunnel_ready: true,
        contradictory_evidence: false,
        hard_drift: false,
        allow_cellular_fallback: false,
        remaining_cellular_budget_mb: 0,
    }
}

#[test]
fn android_wifi_can_never_promote_to_trusted() {
    let d = evaluate_android_connectivity(&obs(AndroidTransport::Wifi));
    assert_eq!(d.authority, ConnectivityAuthority::ProtectedTransport);
}

#[test]
fn unvalidated_wifi_is_denied_even_when_tunnel_flag_is_true() {
    let mut o = obs(AndroidTransport::Wifi);
    o.validated_internet = false;
    let d = evaluate_android_connectivity(&o);
    assert_eq!(d.authority, ConnectivityAuthority::Denied);
    assert_eq!(d.reason, DecisionReason::InsufficientEvidence);
}

#[test]
fn captive_portal_is_denied_until_separately_handled() {
    let mut o = obs(AndroidTransport::Wifi);
    o.captive_portal = true;
    let d = evaluate_android_connectivity(&o);
    assert_eq!(d.authority, ConnectivityAuthority::Denied);
}

#[test]
fn protected_wifi_without_tunnel_fails_closed() {
    let mut o = obs(AndroidTransport::Wifi);
    o.protected_tunnel_ready = false;
    let d = evaluate_android_connectivity(&o);
    assert_eq!(d.authority, ConnectivityAuthority::Denied);
    assert_eq!(d.reason, DecisionReason::ProtectedTransportUnavailable);
}

#[test]
fn cellular_requires_explicit_fallback_and_budget() {
    let mut o = obs(AndroidTransport::Cellular);
    let denied = evaluate_android_connectivity(&o);
    assert_eq!(denied.authority, ConnectivityAuthority::Denied);

    o.allow_cellular_fallback = true;
    o.remaining_cellular_budget_mb = 10;
    let allowed = evaluate_android_connectivity(&o);
    assert_eq!(allowed.authority, ConnectivityAuthority::CellularFallback);
}

#[test]
fn hard_drift_and_contradiction_fail_closed() {
    let mut hard = obs(AndroidTransport::Wifi);
    hard.hard_drift = true;
    assert_eq!(
        evaluate_android_connectivity(&hard).authority,
        ConnectivityAuthority::Denied
    );

    let mut contrad = obs(AndroidTransport::Wifi);
    contrad.contradictory_evidence = true;
    assert_eq!(
        evaluate_android_connectivity(&contrad).authority,
        ConnectivityAuthority::Denied
    );
}

#[test]
fn encoded_protected_transport_has_no_lan_or_direct_dns_bits() {
    let encoded =
        encode_android_decision(evaluate_android_connectivity(&obs(AndroidTransport::Wifi)));
    let effective = (encoded >> 16) & 0xff;
    assert_eq!(effective & (1 << 4), 0);
    assert_eq!(effective & (1 << 5), 0);
    assert_ne!(effective & (1 << 0), 0);
    assert_ne!(effective & (1 << 7), 0);
}
