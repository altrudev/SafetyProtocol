#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceClass {
    Network,
    AgentTool,
    Api,
    BrowserOrigin,
    Peripheral,
    PackageSource,
    Compute,
    ModelEndpoint,
    Iot,
    DataTransfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Authority {
    pub transport: bool,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub local_network: bool,
    pub direct_dns: bool,
    pub credential_use: bool,
    pub data_egress: bool,
}

impl Authority {
    pub const fn none() -> Self {
        Self {
            transport: false,
            read: false,
            write: false,
            execute: false,
            local_network: false,
            direct_dns: false,
            credential_use: false,
            data_egress: false,
        }
    }

    pub fn is_subset_of(&self, ceiling: &Self) -> bool {
        (!self.transport || ceiling.transport)
            && (!self.read || ceiling.read)
            && (!self.write || ceiling.write)
            && (!self.execute || ceiling.execute)
            && (!self.local_network || ceiling.local_network)
            && (!self.direct_dns || ceiling.direct_dns)
            && (!self.credential_use || ceiling.credential_use)
            && (!self.data_egress || ceiling.data_egress)
    }

    pub fn intersect(self, ceiling: Self) -> Self {
        Self {
            transport: self.transport && ceiling.transport,
            read: self.read && ceiling.read,
            write: self.write && ceiling.write,
            execute: self.execute && ceiling.execute,
            local_network: self.local_network && ceiling.local_network,
            direct_dns: self.direct_dns && ceiling.direct_dns,
            credential_use: self.credential_use && ceiling.credential_use,
            data_egress: self.data_egress && ceiling.data_egress,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvidenceLevel {
    #[default]
    Unknown,
    Observed,
    Corroborated,
    Authenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DriftSeverity {
    #[default]
    None,
    Soft,
    Hard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Evidence {
    pub identity: EvidenceLevel,
    pub user_approved: bool,
    pub contradictory: bool,
    pub drift: DriftSeverity,
    pub age_ms: u64,
    pub ttl_ms: u64,
}

impl Evidence {
    pub fn is_fresh(&self) -> bool {
        self.ttl_ms > 0 && self.age_ms <= self.ttl_ms
    }

    pub fn supports_authenticated_identity(&self) -> bool {
        self.is_fresh()
            && self.identity == EvidenceLevel::Authenticated
            && !self.contradictory
            && self.drift != DriftSeverity::Hard
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceBudget {
    pub max_probe_bytes: u64,
    pub max_probe_cpu_ms: u64,
    pub max_retained_evidence_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericDecisionReason {
    GrantedWithinCeiling,
    EvidenceInsufficient,
    EvidenceExpired,
    ContradictoryEvidence,
    HardDrift,
    RequestedAuthorityExceedsCeiling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericDecision {
    pub granted: Authority,
    pub reason: GenericDecisionReason,
}

pub fn decide_authority(
    requested: Authority,
    ceiling: Authority,
    evidence: &Evidence,
) -> GenericDecision {
    if evidence.contradictory {
        return GenericDecision {
            granted: Authority::none(),
            reason: GenericDecisionReason::ContradictoryEvidence,
        };
    }
    if evidence.drift == DriftSeverity::Hard {
        return GenericDecision {
            granted: Authority::none(),
            reason: GenericDecisionReason::HardDrift,
        };
    }
    if evidence.ttl_ms > 0 && !evidence.is_fresh() {
        return GenericDecision {
            granted: Authority::none(),
            reason: GenericDecisionReason::EvidenceExpired,
        };
    }
    if evidence.identity == EvidenceLevel::Unknown {
        return GenericDecision {
            granted: Authority::none(),
            reason: GenericDecisionReason::EvidenceInsufficient,
        };
    }

    let granted = requested.intersect(ceiling);
    let reason = if requested.is_subset_of(&ceiling) {
        GenericDecisionReason::GrantedWithinCeiling
    } else {
        GenericDecisionReason::RequestedAuthorityExceedsCeiling
    };
    GenericDecision { granted, reason }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    pub resource_class: ResourceClass,
    pub requested: Authority,
    pub granted: Authority,
    pub observed_drift: DriftSeverity,
    pub evidence_level: EvidenceLevel,
}

impl Receipt {
    pub fn authority_non_inventing(&self) -> bool {
        self.granted.is_subset_of(&self.requested)
    }
}
