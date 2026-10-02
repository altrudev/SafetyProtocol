# Android VPN enforcement v0.3

Status: experimental fail-closed enforcement shell.

## What v0.3 proves

SafetyProtocol v0.3 adds an Android `VpnService` capture boundary whose promoted behavior is deliberately conservative:

- capture all IPv4 traffic with `0.0.0.0/0`
- capture all IPv6 traffic with `::/0`
- do not call `allowBypass()`
- do not define per-application exclusions
- do not forward packets
- drop captured packets locally
- expose runtime evidence separately from ordinary network observations

This makes v0.3 a fail-closed enforcement shell, not a production VPN transport.

## Authority boundary

`RawAndroidNetworkObservation` no longer contains a caller-controlled `protectedTunnelReady` field.

The public Android engine derives protected transport readiness from `TunnelEnforcementEvidence`. That evidence requires:

1. local TUN capture established,
2. Android independently observing a VPN transport, and
3. an authenticated protected session.

The third condition is intentionally false in v0.3 because an authenticated remote protected transport is not implemented yet. Therefore the public engine cannot accidentally promote this drop-only shell into usable protected forwarding.

## Session fail-closed

A session fail-closed claim is allowed only while:

- `SafetyProtocolVpnService` is running, and
- its local TUN capture descriptor is established.

During v0.3 the TUN reader discards every captured packet. There is no forwarding disposition in the enforcement state model.

## Persistent fail-closed

Persistent fail-closed is a stronger claim. It requires Android to report both:

- always-on VPN enabled, and
- lockdown enabled.

Merely declaring support for always-on in the manifest is not sufficient.

Runtime testing on the Android 15 ATD emulator verified session fail-closed, but persistent fail-closed remained false. Directly writing the emulator's secure settings did not make `VpnService.isAlwaysOn()` or `isLockdownEnabled()` true, so v0.3 does **not** claim persistent fail-closed.

## Real Android runtime evidence

Verified on Android 15 / API 35 AOSP ATD x86_64 emulator.

Observed application result:

    pre=true
    capture=true
    osVpn=true
    alwaysOn=false
    lockdown=false
    sessionFailClosed=true
    persistentFailClosed=false
    post=false

`pre=true` means a TCP connection to the emulator host succeeded before VPN capture. `post=false` means the same probe could no longer connect after the TUN became active.

Android system state independently showed:

- VPN connected for the SafetyProtocol test package
- interface `tun0`
- IPv4 default route through `tun0`
- IPv6 default route through `tun0`
- session ID `SafetyProtocol`
- all application UIDs assigned to the VPN
- `bypassable=false`

## Permissions

The SafetyProtocol Android library requests:

- `ACCESS_NETWORK_STATE`
- `FOREGROUND_SERVICE`
- `FOREGROUND_SERVICE_SYSTEM_EXEMPTED`

The library does not request `INTERNET`, location, nearby-Wi-Fi, or exact-alarm permissions in this slice.

The separate `runtime-test-app` requests `INTERNET` only so the test can establish a known connection before VPN capture and prove it is blocked afterward.

## Foreground service type

The VpnService uses the Android `systemExempted` foreground-service type. Android documents VPN apps configured through system VPN settings as an eligible `systemExempted` case. Android lint currently models a narrower exact-alarm eligibility branch, so the manifest contains a narrowly scoped lint suppression on the VpnService declaration rather than requesting an unrelated exact-alarm permission.

## Not implemented / claim ceiling

v0.3 does not yet provide:

- an authenticated remote tunnel endpoint
- packet encryption/encapsulation to a remote server
- forwarding from the TUN to a protected transport
- independent remote endpoint attestation
- DNS forwarding
- automatic network switching
- runtime-verified always-on/lockdown persistence

A future transport engine must use `VpnService.protect()` for its own transport socket before forwarding is enabled, otherwise the transport could loop back into the VPN.
