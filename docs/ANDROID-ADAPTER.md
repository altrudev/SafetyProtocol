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

This v0.2 slice is the Android observation adapter and safety gate. It is not yet a JNI/FFI binding to the Rust reference core, a VPN implementation, an auto-connect engine, or a production application.

The next integration slice should bind this observation contract to the shared core without duplicating policy semantics inside Android.

## Build

Requires Android SDK API 37, Build Tools 37.0.0, Gradle 9.8+, and JDK 17+.

    gradle :android-adapter:testDebugUnitTest
    gradle :android-adapter:lintDebug
    gradle :android-adapter:assembleRelease

Or run:

    scripts/frequency-sweep.sh

## Tooling note

With AGP 9.4.1 on Gradle 9.8, Gradle reports an upstream deprecation involving Configuration.setVisible(boolean). The adapter tests, lint and release build pass. This is retained as a build-tool compatibility observation for a future Gradle 10/11 migration; it is not currently a runtime or protocol warning.
