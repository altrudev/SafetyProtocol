use safetyprotocol::*;

fn authority_from_bits(bits: u8) -> Authority {
    Authority {
        transport: bits & 1 != 0,
        read: bits & 2 != 0,
        write: bits & 4 != 0,
        execute: bits & 8 != 0,
        local_network: bits & 16 != 0,
        direct_dns: bits & 32 != 0,
        credential_use: bits & 64 != 0,
        data_egress: bits & 128 != 0,
    }
}

#[test]
fn all_authority_combinations_obey_non_invention_and_ceiling() {
    let evidence = Evidence {
        identity: EvidenceLevel::Observed,
        user_approved: true,
        contradictory: false,
        drift: DriftSeverity::None,
        age_ms: 1,
        ttl_ms: 100,
    };

    for requested_bits in 0u8..=255 {
        for ceiling_bits in 0u8..=255 {
            let requested = authority_from_bits(requested_bits);
            let ceiling = authority_from_bits(ceiling_bits);
            let decision = decide_authority(requested, ceiling, &evidence);
            assert!(decision.granted.is_subset_of(&requested));
            assert!(decision.granted.is_subset_of(&ceiling));
        }
    }
}

#[test]
fn adversarial_connectivity_matrix_preserves_security_invariants() {
    for bits in 0u16..=255 {
        let c = NetworkCandidate {
            user_approved: bits & 1 != 0,
            known_identity: bits & 2 != 0,
            open_network: bits & 4 != 0,
            captive_portal: bits & 8 != 0,
            fingerprint_matches: bits & 16 != 0,
            contradictory_evidence: bits & 32 != 0,
            hard_drift: bits & 64 != 0,
            protected_tunnel_ready: bits & 128 != 0,
            estimated_cost_microunits_per_mb: 0,
        };
        let d = evaluate(&c, &Policy::default());

        match d.authority {
            ConnectivityAuthority::Trusted => {
                assert!(c.user_approved);
                assert!(c.known_identity);
                assert!(!c.open_network);
                assert!(!c.captive_portal);
                assert!(c.fingerprint_matches);
                assert!(!c.contradictory_evidence);
                assert!(!c.hard_drift);
            }
            ConnectivityAuthority::ProtectedTransport => {
                assert!(c.protected_tunnel_ready);
                assert!(!d.effective.local_network);
                assert!(!d.effective.direct_dns);
                assert!(d.protected_tunnel_required);
            }
            ConnectivityAuthority::Denied => {
                assert_eq!(d.effective, Authority::none());
            }
            ConnectivityAuthority::CellularFallback => {
                panic!("cellular fallback cannot occur when it was not requested");
            }
        }

        if c.contradictory_evidence || c.hard_drift {
            assert_eq!(d.authority, ConnectivityAuthority::Denied);
        }
    }
}
