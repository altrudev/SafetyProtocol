# Android Native Core Binding ABI v1

Status: experimental.

## Purpose

The Android adapter calls the same Rust SafetyProtocol connectivity policy used by the public reference core. Android does not carry an independent copy of the authority rules.

## JNI inputs

The native evaluation entry point accepts only:

- transport class
- Android validated-Internet state
- captive-portal state
- protected-tunnel-ready observation
- contradiction state
- hard-drift state
- explicit cellular-fallback permission
- remaining cellular budget

It does not accept SSID, BSSID, location, a Trusted flag, authenticated identity, arbitrary granted authority, or a caller-selected decision reason.

Fields such as `userApproved` and `ssidKnown` that may exist in Android-side observation objects are deliberately not part of the native ABI and therefore cannot promote the Rust decision.

## Claim ceiling

`protectedTunnelReady` is currently a caller-supplied observation. ABI v1 does not independently attest that a VPN/tunnel is established, that all application traffic is captured, or that the remote tunnel endpoint is authentic.

Therefore a `ProtectedTransport` decision means:

> Given the supplied observation that protected transport is ready, the core permits only the constrained transport authority encoded by the decision.

It does not independently prove that the protected path exists or is enforcing traffic. That requires a later VpnService/tunnel observation and enforcement slice.

## Encoded decision

The JNI method returns one signed 64-bit integer used as a compact local ABI value.

- bits 0..7: connectivity authority
- bits 8..15: decision reason
- bits 16..23: effective authority capability bits
- bit 24: protected tunnel required
- remaining bits: reserved and currently zero

Authority codes:

- 0 Trusted
- 1 ProtectedTransport
- 2 CellularFallback
- 3 Denied

ABI v1 Android observations cannot produce Trusted.

## Effective authority bits

- bit 0 transport
- bit 1 read
- bit 2 write
- bit 3 execute
- bit 4 local network
- bit 5 direct DNS
- bit 6 credential use
- bit 7 data egress

Protected public Wi-Fi currently receives transport + data-egress authority only. It does not receive local-network or direct-DNS authority.

## Fail-closed cases

The Android binding denies:

- contradictory evidence
- hard drift
- unvalidated Wi-Fi
- captive-portal Wi-Fi in the general data path
- protected Wi-Fi without the protected-tunnel-ready observation
- cellular fallback without explicit permission
- cellular fallback with no remaining budget
- unsupported/unknown transports in this profile

## Native targets

The promoted build produces:

- arm64-v8a from Rust target aarch64-linux-android
- x86_64 from Rust target x86_64-linux-android

No JNI helper crate is required; the exported surface uses primitive JNI-compatible values only.
