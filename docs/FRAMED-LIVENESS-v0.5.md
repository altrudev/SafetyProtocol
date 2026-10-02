# SafetyProtocol Framed Transport and Liveness v0.5

Status: experimental transport protocol foundation.

## Purpose

v0.5 defines a bounded application framing format over the authenticated TLS session introduced in v0.4 and adds challenge/response liveness evidence.

The VPN forwarding path remains disabled.

## Frame format

Each frame uses a fixed 20-byte header followed by a bounded payload:

- 4-byte magic: SPF1
- 1-byte protocol version
- 1-byte frame type
- 2-byte flags (currently zero only)
- 8-byte non-negative sequence number
- 4-byte payload length
- payload

Frame types:

- PING
- PONG
- DATA
- CLOSE

Payloads are limited to 64 KiB. Invalid magic, unsupported version or flags, negative sequence, oversized length, unknown frame type, or truncated payload fails closed with a protocol error.

## Liveness

Production PING challenges use a cryptographically random 16-byte nonce.

A liveness acknowledgement is accepted only when:

- the frame is PONG
- sequence matches the pending challenge
- nonce matches in constant time
- the response arrives before the challenge deadline
- the challenge has not already been consumed

Replays, wrong sequence, wrong nonce, and late responses do not establish fresh liveness.

Freshness expires after the configured freshness window. An overdue pending challenge also removes freshness.

## Readiness composition

`TransportSessionReadiness` requires both:

- authenticated TLS establishment evidence from v0.4
- fresh PING/PONG liveness evidence from v0.5

Only then can `protectedSessionReady` be true in the composed evidence object.

This state is not yet connected to `SafetyProtocolVpnRuntime.protectedSessionAuthenticated`.

`forwardingAuthorized` remains false by construction.

## Data-plane boundary

DATA is a defined bounded frame type, but v0.5 does not connect TUN packets to DATA frames and does not write decoded DATA frames back to the TUN interface.

The presence of a DATA frame type is therefore protocol capability, not evidence that forwarding is active.

## Claim ceiling

v0.5 does not prove:

- a live remote SafetyProtocol server exists
- real PING/PONG exchange across a deployed endpoint
- continuous liveness on a physical Android device
- packet forwarding
- DNS protection
- throughput or compression performance
- anonymity

Those require later runtime slices.
