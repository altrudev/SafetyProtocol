# Frequency SafetyProtocol v0.1 — Experimental Specification

Status: experimental public protocol foundation.

## 1. Purpose

SafetyProtocol governs use of an external resource by separating observation, evidence, requested authority, policy ceiling, effective authority, drift and receipt.

## 2. Normative invariants

Implementations conforming to this experimental profile:

1. MUST NOT treat availability as authorization.
2. MUST NOT treat familiarity as authenticated identity.
3. MUST NOT grant authority greater than the requested authority.
4. MUST NOT grant authority greater than the applicable policy ceiling.
5. MUST grant no authority from contradictory evidence.
6. MUST grant no authority after hard drift until reevaluation establishes a new decision.
7. MUST NOT use expired evidence to promote authority.
8. MUST preserve unknown as distinct from trusted/verified.
9. MUST NOT let cost optimization override a security invariant.
10. MUST NOT let an adapter strengthen an evidence claim without new supporting evidence.
11. SHOULD bound CPU, storage and network work used to evaluate a candidate.
12. SHOULD produce a receipt sufficient to compare requested and granted authority without including secrets.

## 3. Core objects

- ResourceClass: type of external resource.
- Evidence: identity level, freshness, contradiction and drift state.
- Authority: explicit capability dimensions.
- Policy ceiling: maximum authority allowed for the decision context.
- GenericDecision: granted authority plus reason.
- Receipt: resource class, requested authority, granted authority and observed evidence/drift state.
- ResourceBudget: upper bounds for probing and retained evidence.

## 4. Authority calculation

Effective authority is bounded by both requested authority and policy ceiling.

Conceptually:

    effective = requested ∩ policy_ceiling

This intersection is applied only after evidence is eligible to support a decision. Contradictory, hard-drifted, expired or unknown evidence cannot be silently promoted.

## 5. Connectivity specialization

The initial specialization defines:

- Trusted: sufficient current evidence plus explicit user approval.
- ProtectedTransport: untrusted transport usable only under required protection and without local-network/direct-DNS authority.
- CellularFallback: explicitly enabled, budget-bounded fallback.
- Denied: no permitted connectivity authority.

Protected public connectivity MUST fail closed when required protected transport is unavailable.

## 6. Claim ceiling

A SafetyProtocol receipt proves what the implementation recorded about its decision. It does not by itself prove external network identity, remote endpoint behavior, carrier billing, anonymity, execution outcome or independent observation unless those claims are separately evidenced.

## 7. Public boundary

This specification is independent of proprietary Frequency Core implementation details. Compatibility is based on the public protocol semantics, not access to private internals.
