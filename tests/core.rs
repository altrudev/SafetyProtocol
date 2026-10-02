use safetyprotocol::*;

fn observed() -> Evidence {
    Evidence {
        identity: EvidenceLevel::Observed,
        user_approved: false,
        contradictory: false,
        drift: DriftSeverity::None,
        age_ms: 1,
        ttl_ms: 100,
    }
}

#[test]
fn granted_authority_never_exceeds_requested_authority() {
    let requested = Authority {
        read: true,
        ..Authority::none()
    };
    let ceiling = Authority {
        read: true,
        write: true,
        execute: true,
        ..Authority::none()
    };
    let d = decide_authority(requested, ceiling, &observed());
    assert!(d.granted.is_subset_of(&requested));
    assert!(!d.granted.write);
    assert!(!d.granted.execute);
}

#[test]
fn requested_authority_is_clamped_to_policy_ceiling() {
    let requested = Authority {
        read: true,
        write: true,
        execute: true,
        ..Authority::none()
    };
    let ceiling = Authority {
        read: true,
        ..Authority::none()
    };
    let d = decide_authority(requested, ceiling, &observed());
    assert!(d.granted.read);
    assert!(!d.granted.write);
    assert!(!d.granted.execute);
    assert_eq!(
        d.reason,
        GenericDecisionReason::RequestedAuthorityExceedsCeiling
    );
}

#[test]
fn unknown_evidence_grants_nothing() {
    let e = Evidence::default();
    let requested = Authority {
        transport: true,
        read: true,
        ..Authority::none()
    };
    let d = decide_authority(requested, requested, &e);
    assert_eq!(d.granted, Authority::none());
    assert_eq!(d.reason, GenericDecisionReason::EvidenceInsufficient);
}

#[test]
fn expired_evidence_grants_nothing() {
    let mut e = observed();
    e.age_ms = 101;
    e.ttl_ms = 100;
    let requested = Authority {
        read: true,
        ..Authority::none()
    };
    let d = decide_authority(requested, requested, &e);
    assert_eq!(d.granted, Authority::none());
    assert_eq!(d.reason, GenericDecisionReason::EvidenceExpired);
}

#[test]
fn contradictory_evidence_grants_nothing() {
    let mut e = observed();
    e.contradictory = true;
    let requested = Authority {
        read: true,
        ..Authority::none()
    };
    let d = decide_authority(requested, requested, &e);
    assert_eq!(d.granted, Authority::none());
    assert_eq!(d.reason, GenericDecisionReason::ContradictoryEvidence);
}

#[test]
fn hard_drift_grants_nothing() {
    let mut e = observed();
    e.drift = DriftSeverity::Hard;
    let requested = Authority {
        read: true,
        ..Authority::none()
    };
    let d = decide_authority(requested, requested, &e);
    assert_eq!(d.granted, Authority::none());
    assert_eq!(d.reason, GenericDecisionReason::HardDrift);
}

#[test]
fn receipt_can_verify_non_invention() {
    let receipt = Receipt {
        resource_class: ResourceClass::AgentTool,
        requested: Authority {
            read: true,
            ..Authority::none()
        },
        granted: Authority {
            read: true,
            ..Authority::none()
        },
        observed_drift: DriftSeverity::None,
        evidence_level: EvidenceLevel::Authenticated,
    };
    assert!(receipt.authority_non_inventing());
}

#[test]
fn receipt_detects_invented_authority() {
    let receipt = Receipt {
        resource_class: ResourceClass::Api,
        requested: Authority {
            read: true,
            ..Authority::none()
        },
        granted: Authority {
            read: true,
            write: true,
            ..Authority::none()
        },
        observed_drift: DriftSeverity::None,
        evidence_level: EvidenceLevel::Authenticated,
    };
    assert!(!receipt.authority_non_inventing());
}
