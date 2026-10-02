# SafetyProtocol VPN Enforcement v0.3

Status: experimental fail-closed enforcement shell.

## Purpose

v0.3 moves SafetyProtocol from policy-only connectivity decisions toward an enforceable Android traffic boundary.

The Android VpnService establishes a local TUN interface with full IPv4 and IPv6 default routes. In this slice, captured packets are deliberately discarded. There is no forwarding path yet.

The promoted behavior is intentionally conservative:

- no local capture -> no session fail-closed claim
- local capture established -> captured traffic is dropped
- service/capture loss -> session fail-closed claim is withdrawn
- no authenticated protected session -> protected Wi-Fi remains denied by the shared Rust policy core

## Separation of evidence

RawAndroidNetworkObservation no longer contains protectedTunnelReady.

Tunnel readiness can only be derived from TunnelEnforcementEvidence, which combines:

- local TUN capture established by SafetyProtocolVpnService
- Android observation of a VPN transport
- authenticated protected-session evidence

v0.3 deliberately sets authenticated protected-session evidence to false because no protected transport engine is implemented yet.

Therefore the v0.3 runtime cannot promote Wi-Fi to ProtectedTransport. It captures and drops traffic instead.

## Session vs persistent fail-closed

sessionFailClosedVerified means the SafetyProtocol service is running and the local TUN capture interface is established.

persistentFailClosedVerified requires Android to report both:

- always-on VPN enabled
- lockdown enabled

These are distinct claims. Establishing a TUN interface during one service session does not prove that traffic will remain blocked after the process or service stops.

On Android versions below API 29, the adapter does not claim direct observation of always-on or lockdown state.

## Routing boundary

The service captures the IPv4 and IPv6 default routes and does not expose an application bypass or exclusion path in this slice.

## Permissions

The adapter declares only the network-state and foreground-service permissions required by the current VPN shell. It does not request Internet, location, or nearby-Wi-Fi permissions.

## What v0.3 does not prove

v0.3 does not prove:

- authenticated remote tunnel establishment
- encryption to a remote endpoint
- remote endpoint identity
- successful packet forwarding
- DNS protection
- production always-on/lockdown configuration on a real device
- device/OEM behavior
- connectivity across captive portals

Those require later slices and real-device validation.

## Next enforcement slice

The next slice should add an authenticated protected transport engine that independently establishes remote endpoint identity, forwards only after authentication, tears forwarding down immediately on drift/tunnel loss, keeps local capture active while dropping traffic during failure, and emits an enforcement receipt that distinguishes capture, authenticated transport, forwarding, and persistent lockdown state.
