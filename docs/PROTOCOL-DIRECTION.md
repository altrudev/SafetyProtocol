# Protocol Direction

## Core idea
SafetyProtocol governs external resources by granting the minimum effective authority justified by current evidence.

## Required properties
- Unknown is not trusted.
- Availability is not authorization.
- Familiarity is not identity.
- Connection is not trust.
- Encryption is not endpoint proof.
- Previous approval is not permanent authority.
- Drift can only preserve or reduce authority unless new evidence justifies promotion.
- Cost optimization cannot override a security invariant.
- Privacy metadata collection must be separately authorized from connectivity use.
- Every promoted action can produce a compact receipt without secrets.

## First specialization
Connectivity is the first specialization because it combines security, privacy, cost, latency and resource constraints in a measurable way.

## Generalization path
After connectivity:
1. MCP / agent tools
2. API connectors
3. browser origins
4. package sources
5. mesh/community relays
6. compute/model routing
7. IoT/peripherals

Each specialization should be a thin adapter over the same protocol primitives.
