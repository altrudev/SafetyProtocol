# SafetyProtocol Explicit Destination Policy v0.8

Status: explicit destination authorization before forwarding eligibility. Forwarding execution remains disabled.

## Purpose

v0.8 tightens v0.7 from public destination to public destination explicitly allowed by policy.

Public classification is necessary but not sufficient.

## Policy model

DestinationPolicy is constructed from explicit IPv4/IPv6 CIDR rules.

Rules are either ALLOW or DENY.

Evaluation is fail-closed:

- non-public destination scope -> DENY
- no matching rule -> DENY
- longest matching prefix wins
- if ALLOW and DENY have the same most-specific prefix, DENY wins
- address-family mismatch does not match
- malformed CIDR configuration is rejected at construction

A broad allow may therefore be narrowed by a more-specific deny.

## Address handling

Exact destination bytes exist only transiently in the in-memory PacketDestination produced by the packet parser.

They are required to evaluate CIDR policy but are not added to receipts, logs, persistence, analytics, or network telemetry by this slice.

PacketDestination copies parsed address bytes on construction. DestinationRule masks its configured network at construction and keeps the masked byte array private.

CIDR configuration accepts numeric IPv4/IPv6 literals only. Hostnames are rejected rather than resolved.

## Forwarding gate

The forwarding eligibility path now requires all previous v0.3-v0.7 evidence plus a DestinationPolicy ALLOW result.

A public packet with an empty policy is denied.

A public packet matching a more-specific deny is denied.

forwardingActive remains false by construction.

## Claim ceiling

v0.8 does not yet execute TUN-to-DATA forwarding, provide a UI or remote mechanism for editing CIDR policy, persist exact packet destinations, perform DNS-name policy, infer destination trust from DNS names, support fragmented packets or IPv6 extension-header chains, or prove real-device forwarding behavior.

The next execution slice must consume this exact eligibility result rather than re-evaluating or bypassing policy.
