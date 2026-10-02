#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

: "${ANDROID_SDK_ROOT:=$HOME/.local/android-sdk}"
export ANDROID_SDK_ROOT
export ANDROID_HOME="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
NDK_VERSION="30.0.16248370"

echo "== Toolchain prerequisites =="
test -x "$ANDROID_SDK_ROOT/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
rustup target list --installed | grep -Fxq aarch64-linux-android
rustup target list --installed | grep -Fxq x86_64-linux-android

echo "== Rust core =="
cargo fmt --check
cargo test --quiet
cargo clippy --all-targets --all-features -- -D warnings

echo "== Android/JNI/enforcement tests =="
gradle :android-adapter:testDebugUnitTest

echo "== Android lint =="
gradle :android-adapter:lintDebug

echo "== Android release AAR =="
gradle :android-adapter:assembleRelease

echo "== Runtime test app build =="
gradle :runtime-test-app:assembleDebug

echo "== Native architectures =="
ARM_LIB="android-adapter/src/main/jniLibs/arm64-v8a/libsafetyprotocol.so"
X86_LIB="android-adapter/src/main/jniLibs/x86_64/libsafetyprotocol.so"
test -f "$ARM_LIB"
test -f "$X86_LIB"
file "$ARM_LIB" | grep -Eq 'ARM aarch64|ARM64'
file "$X86_LIB" | grep -q 'x86-64'
file "$ARM_LIB" | grep -q 'stripped'
file "$X86_LIB" | grep -q 'stripped'
if readelf -S "$ARM_LIB" | grep -Eq '\.debug_|\.zdebug_'; then exit 24; fi
if readelf -S "$X86_LIB" | grep -Eq '\.debug_|\.zdebug_'; then exit 25; fi

echo "== JNI symbol boundary =="
readelf -Ws "$ARM_LIB" | grep -q 'Java_dev_altru_safetyprotocol_android_SafetyProtocolNative_nativeAbiVersion'
readelf -Ws "$ARM_LIB" | grep -q 'Java_dev_altru_safetyprotocol_android_SafetyProtocolNative_nativeEvaluateConnectivity'

echo "== AAR native/service contents =="
AAR="android-adapter/build/outputs/aar/android-adapter-release.aar"
test -f "$AAR"
unzip -l "$AAR" | grep -q 'jni/arm64-v8a/libsafetyprotocol.so'
unzip -l "$AAR" | grep -q 'jni/x86_64/libsafetyprotocol.so'
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
unzip -q "$AAR" classes.jar -d "$tmp"
jar tf "$tmp/classes.jar" | grep -q 'SafetyProtocolVpnService.class'
jar tf "$tmp/classes.jar" | grep -q 'VpnEnforcementPolicy.class'
jar tf "$tmp/classes.jar" | grep -q 'PinnedTlsProtectedTransport.class'
rm -rf "$tmp"
trap - EXIT

echo "== Android permission/service boundary =="
manifest="android-adapter/src/main/AndroidManifest.xml"
grep -Fq 'android.permission.ACCESS_NETWORK_STATE' "$manifest"
grep -Fq 'android.permission.INTERNET' "$manifest"
grep -Fq 'android.permission.FOREGROUND_SERVICE' "$manifest"
grep -Fq 'android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED' "$manifest"
grep -Fq 'android.permission.BIND_VPN_SERVICE' "$manifest"
grep -Fq 'android:foregroundServiceType="systemExempted"' "$manifest"
grep -Fq 'android.net.VpnService.SUPPORTS_ALWAYS_ON' "$manifest"
if grep -Eq 'ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|NEARBY_WIFI_DEVICES|SCHEDULE_EXACT_ALARM|USE_EXACT_ALARM' "$manifest"; then
  echo "Unexpected library permission" >&2
  exit 20
fi

echo "== VPN enforcement boundary =="
service="android-adapter/src/main/java/dev/altru/safetyprotocol/android/SafetyProtocolVpnService.kt"
grep -Fq '.setBlocking(true)' "$service"
grep -Fq '.addRoute("0.0.0.0", 0)' "$service"
grep -Fq '.addRoute("::", 0)' "$service"
grep -Fq '.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)' "$service"
if grep -RInE 'allowBypass\(|addDisallowedApplication\(|addAllowedApplication\(' android-adapter/src/main/java; then
  echo "VPN bypass/application-exclusion surface found" >&2
  exit 26
fi
if grep -Fq 'protectedTunnelReady' android-adapter/src/main/java/dev/altru/safetyprotocol/android/AndroidNetworkObservation.kt; then
  echo "Raw network observation can assert tunnel readiness" >&2
  exit 27
fi
if grep -q 'FORWARD' android-adapter/src/main/java/dev/altru/safetyprotocol/android/VpnEnforcement.kt; then
  echo "Forwarding state introduced into drop-only v0.3 shell" >&2
  exit 28
fi

echo "== Forbidden Android identity/control API scan =="
if grep -RInE 'getSSID|getBSSID|ScanResult|WifiManager|startScan|requestNetwork|bindProcessToNetwork' android-adapter/src/main/java; then
  echo "Forbidden Android identity/control surface found" >&2
  exit 21
fi

echo "== Native ABI authority-invention scan =="
if grep -nE 'userApproved|ssidKnown|BSSID|SSID|location|grantedAuthority|trusted[[:space:]]*:' src/android_jni.rs; then
  echo "JNI ABI accepts a prohibited trust/identity surface" >&2
  exit 22
fi

echo "== Secret / endpoint scan =="
if grep -RInE 'api[_-]?key|access[_-]?token|password|secret|https?://' android-adapter/src/main/java android-adapter/src/test/java src/android.rs src/android_jni.rs; then
  echo "Sensitive indicator found" >&2
  exit 23
fi

echo "== Cargo package =="
cargo package --allow-dirty >/dev/null
test "$(cargo tree --prefix none | wc -l)" -eq 1



echo "== VPN v0.3 enforcement boundary =="
VPN_SERVICE="android-adapter/src/main/java/dev/altru/safetyprotocol/android/SafetyProtocolVpnService.kt"
RAW_OBS="android-adapter/src/main/java/dev/altru/safetyprotocol/android/AndroidNetworkObservation.kt"
SNAPSHOT="android-adapter/src/main/java/dev/altru/safetyprotocol/android/AndroidNetworkSnapshotReader.kt"
MANIFEST="android-adapter/src/main/AndroidManifest.xml"

grep -Fq '.addRoute("0.0.0.0", 0)' "$VPN_SERVICE"
grep -Fq '.addRoute("::", 0)' "$VPN_SERVICE"
grep -Fq 'android.permission.BIND_VPN_SERVICE' "$MANIFEST"
grep -Fq 'android:exported="false"' "$MANIFEST"

if grep -RIn 'protectedTunnelReady' "$RAW_OBS" "$SNAPSHOT"; then
  echo "Raw network observation must not assert protected-tunnel readiness" >&2
  exit 30
fi

if grep -Eq 'ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|NEARBY_WIFI_DEVICES' "$MANIFEST"; then
  echo "Unexpected location/nearby permission" >&2
  exit 31
fi

if grep -RInE 'FORWARD|forwardPacket' android-adapter/src/main/java/dev/altru/safetyprotocol/android/VpnEnforcement.kt "$VPN_SERVICE"; then
  echo "v0.3 must not expose packet forwarding" >&2
  exit 32
fi

echo "== Protected transport v0.4 boundary =="
TRANSPORT="android-adapter/src/main/java/dev/altru/safetyprotocol/android/ProtectedTransport.kt"
grep -Fq 'socketProtector.protect(rawSocket)' "$TRANSPORT"
grep -Fq 'endpointIdentificationAlgorithm = "HTTPS"' "$TRANSPORT"
grep -Fq 'MessageDigest.getInstance("SHA-256")' "$TRANSPORT"
grep -Fq 'MessageDigest.isEqual(endpoint.spkiSha256, actualPin)' "$TRANSPORT"
grep -Fq 'forwardingAuthorized: Boolean = false' "$TRANSPORT"
if grep -RInE 'TrustManager|HostnameVerifier|ALLOW_ALL|trustAll|setDefaultHostnameVerifier' "$TRANSPORT"; then
  echo "Custom/permissive TLS trust surface found" >&2
  exit 33
fi
if grep -RInE 'protectedSessionAuthenticated[[:space:]]*=[[:space:]]*true' android-adapter/src/main/java; then
  echo "v0.4 must not promote authenticated establishment into runtime tunnel readiness" >&2
  exit 34
fi

echo "== Diff hygiene =="
git diff --check

RUNTIME_STATUS="NOT VERIFIED"
if [[ "${SAFETYPROTOCOL_RUNTIME_DEVICE:-0}" == "1" ]]; then
    echo "== Real Android runtime smoke =="
    scripts/android-vpn-runtime-smoke.sh
    RUNTIME_STATUS="PASS"
else
    echo "== Real Android runtime smoke == NOT VERIFIED (set SAFETYPROTOCOL_RUNTIME_DEVICE=1)"
fi

echo "Frequency static/build sweep PASS"
echo "Frequency real-device VPN runtime: ${RUNTIME_STATUS}"
