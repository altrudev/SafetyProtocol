# SafetyProtocol Constrained Forwarding Gate v0.6

Status: forwarding eligibility only; packet forwarding remains disabled.

## Purpose

v0.6 binds the evidence developed in v0.3-v0.5 into one fail-closed forwarding-eligibility decision.

A DATA frame is eligible only when all of the following are true at the same decision point:

- SafetyProtocol VPN service is running
- local TUN capture is established
- Android independently observes the VPN transport
- runtime-owned protected-session readiness is still fresh at the current monotonic time
- the Rust core decision is PROTECTED_TRANSPORT for the current network observation
- the Rust reason is PROTECTED_TRANSPORT_ONLY
- the Rust decision requires the protected tunnel
- effective authority is exactly transport + data egress and does not include local-network, direct-DNS, credential, read, write, or execute authority
- candidate relay host, port, and SPKI SHA-256 pin match the authenticated endpoint
- frame type is DATA
- DATA payload is non-empty and already within the SPF1 frame bound

Any mismatch returns DROP.

## Freshness is checked at use time

Transport readiness now carries a monotonic valid-until time derived from the successful liveness acknowledgement.

SafetyProtocolVpnRuntime rechecks that expiry every time it produces tunnel evidence. A stale stored readiness object therefore cannot keep protectedTunnelReady true.

The forwarding gate performs the same current-time check before returning ELIGIBLE.

## Runtime ownership

Raw Android network observations still cannot assert tunnel readiness.

The VPN runtime stores the derived TransportSessionReadiness object internally. The forwarding gate reads that exact runtime-owned object rather than accepting a second readiness object from a caller.

VPN/capture loss clears stored session readiness.

## Rust policy binding

Fresh derived readiness may now make protectedTunnelReady true for the JNI call. The shared Rust policy core can therefore return PROTECTED_TRANSPORT when the remaining Wi-Fi evidence satisfies its policy.

When readiness expires, the same observation returns to the fail-closed decision path.

## Endpoint binding

Eligibility is tied to the authenticated relay endpoint using:

- hostname comparison
- exact port comparison
- constant-time SPKI SHA-256 pin comparison

A different host, port, or public-key pin is not eligible.

## Execution boundary

ELIGIBLE does not mean packets are being forwarded.

`forwardingActive` is false by construction in v0.6. The existing VpnService packet loop continues to discard captured traffic.

## Claim ceiling

v0.6 does not yet parse inner IPv4/IPv6 packets and therefore does not enforce destination CIDR, protocol, or destination-port policy over the encapsulated packet.

Because that data-flow evidence is not yet implemented, forwarding execution remains disabled.

The next slice should add bounded packet metadata parsing and destination/data-flow policy, test it adversarially, and only then consider wiring eligible TUN packets into DATA frames.
