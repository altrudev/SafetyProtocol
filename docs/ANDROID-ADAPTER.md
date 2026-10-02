# Android Connectivity Adapter v0.2

Status: experimental adapter foundation.

## Boundary

The Android adapter observes platform network state and produces a privacy-minimized observation for SafetyProtocol policy evaluation.

It does not authenticate network identity and it does not grant Trusted authority.

The adapter currently requests only:

- android.permission.ACCESS_NETWORK_STATE

It intentionally does not request or use:

- ACCESS_FINE_LOCATION
- ACCESS_COARSE_LOCATION
- NEARBY_WIFI_DEVICES
- SSID or BSSID access
- Wi-Fi scanning
- active network selection
- process network binding

## Observable inputs

The platform reader currently observes:

- active transport class
- Android validated-Internet capability
- captive-portal capability
- whether the protected tunnel is reported ready by the caller
- contradiction / hard-drift state supplied by the assurance layer

Android-reported Wi-Fi state is treated as untrusted transport evidence. It cannot create authenticated identity.

## Fail-closed behavior

The adapter emits a DENY recommendation when:

- contradictory evidence is present
- hard drift is present
- Wi-Fi requires protected transport but the protected tunnel is unavailable

A non-denied result means only "forward this observation to policy." It is not a grant of trust or network authority.

## Current implementation limit

This v0.2 slice now includes a JNI binding to the shared Rust reference core. Android observations are evaluated by the Rust policy engine rather than by a second Kotlin policy implementation. The native ABI is documented in `docs/ANDROID-NATIVE-ABI.md`.

It is not yet a VPN implementation, independent tunnel attestation/enforcement layer, auto-connect engine, or production application.

## Build

Requires Android SDK API 37, Build Tools 37.0.0, Gradle 9.8+, and JDK 17+.

    gradle :android-adapter:testDebugUnitTest
    gradle :android-adapter:lintDebug
    gradle :android-adapter:assembleRelease

Or run:

    scripts/frequency-sweep.sh

## Tooling note

With AGP 9.4.1 on Gradle 9.8, Gradle reports an upstream deprecation involving Configuration.setVisible(boolean). The adapter tests, lint and release build pass. This is retained as a build-tool compatibility observation for a future Gradle 10/11 migration; it is not currently a runtime or protocol warning.


The Rust release profile strips the generated Android shared libraries before AAR packaging. AGP may report that it cannot strip them again; direct ELF inspection verifies the promoted ARM64 and x86_64 libraries are already stripped and contain no debug sections.

## Enforcement shell

The Android adapter now includes the v0.3 fail-closed `VpnService` shell documented in `docs/VPN-ENFORCEMENT.md`. The service captures IPv4 and IPv6 default routes and drops packets locally. It does not yet forward traffic to an authenticated protected transport.

Runtime evidence is kept separate from raw network observations; ordinary Android network state can no longer assert that a protected tunnel is ready.
