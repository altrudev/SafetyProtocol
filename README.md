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


## Framed transport and liveness v0.5

SafetyProtocol now includes a bounded SPF1 transport frame format plus replay-resistant PING/PONG liveness evidence. Authenticated establishment and fresh liveness can compose into protected-session readiness evidence, but the VPN runtime is not promoted and packet forwarding remains disabled. See docs/FRAMED-LIVENESS-v0.5.md.


## Constrained forwarding gate v0.6

SafetyProtocol now composes TUN capture, OS VPN corroboration, expiring authenticated-session readiness, Rust PROTECTED_TRANSPORT authority, exact narrow capability scope, authenticated relay binding, and bounded DATA frames into a fail-closed forwarding-eligibility decision. Forwarding execution remains disabled pending packet-level destination/data-flow enforcement. See docs/CONSTRAINED-FORWARDING-GATE-v0.6.md.


## Packet metadata and flow policy v0.7

SafetyProtocol now parses bounded IPv4/IPv6 packet metadata before a DATA frame can become forwarding-eligible. Malformed, fragmented, local/private, link-local, loopback, multicast, reserved, and unsupported-protocol traffic fails closed. Forwarding execution remains disabled. See docs/PACKET-FLOW-POLICY-v0.7.md.


## Explicit destination policy v0.8

SafetyProtocol now requires an explicit IPv4/IPv6 CIDR allow decision after packet parsing and before forwarding eligibility. No matching allow rule means deny; longest-prefix matching applies and deny wins ties. Exact destination bytes remain transient in memory and are not persisted. Forwarding execution remains disabled. See docs/DESTINATION-POLICY-v0.8.md.


## Loopback forwarding executor v0.9

SafetyProtocol now has an internal, unconnected execution-gating primitive that snapshots the exact DATA frame, invokes the existing ForwardingGate at execution time, rejects replay/out-of-order sequences, and permanently fails closed after an unknown writer failure. No production sink or VPN call site exists yet, so real forwarding remains disabled. See docs/LOOPBACK-EXECUTOR-v0.9.md.


## Session execution revision v0.10

SafetyProtocol now binds each test-sink execution attempt to a composite session/runtime revision. Policy, relay, destination policy, and live VPN runtime updates cannot commit between gate evaluation and the test sink write; same-thread reentrant mutation is explicitly rejected. Revision evidence is carried on both executed and denied attempts. Real forwarding remains disabled. See docs/EXECUTION-REVISION-v0.10.md.


## Bounded execution permits v0.11

SafetyProtocol now has executor-bound, single-use forwarding permits with hard TTL/write-budget ceilings, cancellation, composite-revision matching, consumption-time gate revalidation, and privacy-minimized in-memory receipts. A sink failure or missed cooperative write deadline poisons the executor. No production network sink or TUN forwarding path is enabled. See docs/EXECUTION-PERMIT-v0.11.md.


## Durable receipts and bounded async handoff v0.12

SafetyProtocol now requires a receipt store for permit execution, includes a bounded SHA-256 hash-chained local receipt journal with a committed-count/last-hash anchor, and has a test-only asynchronous handoff adapter with bounded cancellation grace. Receipt persistence failure poisons future execution without rewriting the actual action outcome. No production async writer or real forwarding path is connected. See docs/DURABLE-RECEIPTS-ASYNC-v0.12.md.


## Transport cancellation proof v0.13

SafetyProtocol now has an allowlisted cancelable framed writer bound to ProtectedTransportSession.close(), plus bounded asynchronous cancellation that requires both successful cancellation return and write-worker quiescence inside one grace deadline. Confirmed cancellation proves no later application-level framed emission by that writer; it does not claim that already-buffered TLS/kernel bytes cannot drain onto the wire. No production forwarding path is connected. See docs/TRANSPORT-CANCELLATION-v0.13.md.


## Synthetic-media disclosure v0.14

SafetyProtocol now includes an experimental disclosure gate for humanlike synthetic media. The key invariant is that visual glitches, identity drift, frame instability, or other generator artifacts are **never** treated as disclosure evidence. Human-visible indication, spoken disclosure freshness, and optional watermark/provenance attestation are evaluated as explicit independent channels. See `docs/SYNTHETIC-MEDIA-DISCLOSURE-v0.14.md`.
