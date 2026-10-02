# SafetyProtocol Packet Metadata and Flow Policy v0.7

Status: packet understanding and forwarding eligibility hardening. Forwarding execution remains disabled.

## Purpose

v0.7 adds bounded IPv4/IPv6 packet metadata parsing before a DATA frame can reach the forwarding-eligibility gate.

The parser is independently bounded to 65,535 bytes and does not rely on the outer SPF1 frame ceiling for safety.

## Parsed evidence

For accepted packets SafetyProtocol derives only the metadata currently needed for policy:

- IP version
- transport protocol (TCP, UDP, or OTHER)
- destination scope
- destination port for TCP/UDP
- packet length

Exact destination addresses are not persisted in this slice.

## Fail-closed parsing

IPv4 is rejected for truncation, invalid IHL, declared-length mismatch, fragmentation, invalid TCP header/data offset, invalid UDP length, and destination port zero.

IPv6 is rejected for truncation, declared-length mismatch, jumbogram form, extension-header chains, invalid TCP/UDP transport headers, and destination port zero.

Unsupported transport protocols may be parsed as OTHER, but flow policy denies them.

## Destination scope

The parser distinguishes PUBLIC, LOCAL_PRIVATE, LINK_LOCAL, LOOPBACK, MULTICAST, UNSPECIFIED, BROADCAST, and RESERVED.

Local/private includes RFC1918-style IPv4 space, carrier-grade shared space, and IPv6 unique-local space. Reserved handling also covers selected documentation, benchmark, special-use, and IPv4-mapped IPv6 ranges.

The classification is intentionally conservative. A destination classified as non-public is not eligible for the current protected-public-Wi-Fi forwarding authority.

## DNS

TCP/UDP destination port 53 to a PUBLIC destination is recognized as DNS over the protected transport. This does not grant direct-DNS authority.

## Forwarding gate integration

A DATA frame must now contain a parseable packet. PacketFlowPolicy must then return ALLOW_TO_FORWARDING_GATE.

Malformed packets and unauthorized destination scopes are rejected before forwarding eligibility can be returned.

forwardingActive remains false by construction and the VPN service continues to drop captured traffic.

## Claim ceiling

v0.7 does not yet forward TUN packets, enforce a user-configurable CIDR allowlist, persist exact destinations, validate IPv4/TCP/UDP checksums, support IPv6 extension headers or fragmented packets, authorize ICMP/ICMPv6, or prove real-device packet behavior for this slice.
