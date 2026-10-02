# Frequency SafetyProtocol

Public repository: https://github.com/altrudev/SafetyProtocol

Frequency SafetyProtocol is a small public reference protocol for granting external resources only the authority justified by current evidence.

The first specialization is secure connectivity: trusted Wi-Fi, protected public transport, and bounded cellular fallback. The protocol core is intentionally domain-neutral so the same authority/evidence/drift model can later be adapted to MCP tools, APIs, browser origins, peripherals, package sources, compute, model endpoints and IoT.

## Core flow

Observation -> Evidence -> Policy Decision -> Effective Authority -> Action -> Drift -> Receipt

## Invariants

- Unknown != trusted.
- Availability != authorization.
- Familiarity != identity.
- Connection != trust.
- Encryption != endpoint proof.
- Previous approval != permanent authority.
- Granted authority cannot exceed requested authority.
- Granted authority cannot exceed the policy ceiling.
- Contradictory evidence fails closed.
- Hard drift fails closed pending reevaluation.
- Expired evidence cannot justify promotion.
- Cost optimization cannot override security policy.
- Receipts cannot invent authority.

## Reference implementation

The current Rust reference core has no third-party runtime dependencies. Connectivity is the first adapter/specialization.

The experimental Android observation adapter is documented in docs/ANDROID-ADAPTER.md. It uses only ACCESS_NETWORK_STATE and cannot promote Android network observations into authenticated trust.

Run:

    cargo test
    cargo clippy --all-targets --all-features -- -D warnings
    cargo build --release

## Public / proprietary boundary

This repository is an independent public reference implementation of SafetyProtocol concepts. It does not contain proprietary Frequency Core implementation logic, private policies, internal assurance machinery, credentials or deployment secrets.

## Status

Experimental protocol foundation. Not yet a production VPN, network manager, anonymity system, carrier replacement, or authorization to access networks without permission.

Copyright © 2026 Val Rukhaylo / Altru.dev.

See `docs/VPN-ENFORCEMENT.md` for the experimental Android fail-closed enforcement shell.


## Protected transport v0.4

The Android adapter now includes an experimental protected TLS session primitive. It protects the underlying socket from the VPN loop, uses platform TLS hostname verification, and requires a configured SHA-256 SPKI pin. Authenticated establishment does not authorize forwarding and does not yet promote runtime tunnel readiness. See docs/PROTECTED-TRANSPORT-v0.4.md.
