# Frequency SafetyProtocol — Reusable Surfaces

Frequency SafetyProtocol is not limited to Wi-Fi. Its reusable primitive is:

Observation -> Evidence -> Policy Decision -> Effective Authority -> Action -> Drift -> Receipt

The public protocol should stay domain-neutral at the core and add thin adapters for each resource class.

## 1. Mobile and desktop connectivity
Use case: choose among trusted Wi-Fi, protected public Wi-Fi, cellular, Ethernet, tethering, community networks and approved relays.
How: network adapter translates platform observations into protocol evidence; policy returns the minimum authority required for transport.

## 2. Browser origin safety
Use case: constrain what a newly encountered site or embedded origin can access.
How: browser adapter maps origin identity, TLS state, prior approvals, requested permissions and behavioral drift into an authority decision.
Possible controls: clipboard, camera, microphone, local network, downloads, storage, cross-origin calls.

## 3. MCP and agent-tool safety
Use case: prevent an MCP server or agent tool from gaining broad authority merely because it is installed or reachable.
How: each server/tool is treated as a resource provider; declared capability, authenticated identity, requested action and observed behavior are evaluated before invocation.
Possible controls: read-only, bounded write, network destination, filesystem scope, credential scope, execution prohibition.

## 4. API and SaaS connectors
Use case: keep integrations from accumulating permanent broad tokens.
How: evaluate endpoint identity, action type, token scope, data class and destination before granting a short-lived effective authority.
Possible controls: read vs write, record scope, rate budget, data egress, destructive actions.

## 5. USB and peripheral devices
Use case: safely attach storage, cameras, serial devices, keyboards, debugging hardware and unknown peripherals.
How: device identity plus observed class and requested operation determine authority.
Possible controls: read-only mount, no autorun, no HID trust, no network bridge, one-session authorization.

## 6. Package registries and software supply
Use case: choose mirrors, package sources and build dependencies without turning source availability into trust.
How: source identity, checksums, signatures, provenance and drift determine whether bytes may be fetched, cached, built or promoted.
Possible controls: fetch-only, quarantine, checksum-required, signature-required, build-isolated.

## 7. Community and mesh networking
Use case: allow peer-to-peer or community relays without granting peers broad device authority.
How: gateway/peer can receive only transport or relay capability with explicit quotas and expiration.
Possible controls: byte budget, duration, no LAN discovery, no inbound sessions, no identity sharing.

## 8. Cloud and edge compute
Use case: use free/low-cost compute resources safely.
How: compute provider is treated as an external capability provider; task sensitivity, code/data classification, execution environment and attestation evidence determine what may leave the device.
Possible controls: public-data-only, encrypted input, no secrets, ephemeral jobs, result verification.

## 9. AI model routing
Use case: route prompts/tasks among local, free, paid and specialized models while respecting privacy and cost.
How: model endpoint identity, data sensitivity, cost, retention policy and task authority become policy inputs.
Possible controls: local-only data, redacted data, no-training endpoint required, spending cap, result marked unverified.

## 10. Smart-home / IoT isolation
Use case: permit useful IoT behavior without granting devices broad LAN authority.
How: each device receives action-specific network authority.
Possible controls: cloud-only, local-controller-only, no peer access, outbound destination allowlist, automatic demotion on drift.

## 11. Public kiosks and shared computers
Use case: safely use printers, scanners, temporary accounts and public terminals.
How: shared resource gets narrowly scoped, session-bound authority that expires automatically.
Possible controls: one document, one print job, no retained credentials, ephemeral storage.

## 12. Data-transfer and synchronization
Use case: move data through free/cheap paths without leaking sensitive content.
How: connectivity authority is combined with data handling class.
Possible controls: defer large sync until safe free path, compress eligible data, never transform or compress secrets in a way that weakens encryption boundaries.

## Product shape

Core protocol:
- generic ResourceIdentity
- Observation
- EvidenceSet
- RequestedAuthority
- PolicyDecision
- EffectiveAuthority
- DriftEvent
- Receipt
- ResourceBudget

Adapters:
- Android/network
- desktop/network
- browser
- MCP
- API
- USB
- packages
- mesh
- compute
- model routing
- IoT

Views:
- simple user reason: why allowed / why blocked
- developer evidence view
- privacy view
- budget / resource view

## Non-invention rule

An adapter may translate evidence into the common protocol but may not promote a weak observation into a stronger identity, trust, provenance, authorization or verification claim.

## Resource rule

Security checks must have bounded CPU, memory, network and storage costs. A resource provider cannot force unbounded probing merely by appearing as a candidate.
