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

echo "== Android/JNI unit tests =="
gradle :android-adapter:testDebugUnitTest

echo "== Android lint =="
gradle :android-adapter:lintDebug

echo "== Android release AAR =="
gradle :android-adapter:assembleRelease

echo "== Native architectures =="
ARM_LIB="android-adapter/src/main/jniLibs/arm64-v8a/libsafetyprotocol.so"
X86_LIB="android-adapter/src/main/jniLibs/x86_64/libsafetyprotocol.so"
test -f "$ARM_LIB"
test -f "$X86_LIB"
file "$ARM_LIB" | grep -Eq 'ARM aarch64|ARM64'
file "$X86_LIB" | grep -q 'x86-64'
file "$ARM_LIB" | grep -q 'stripped'
file "$X86_LIB" | grep -q 'stripped'
if readelf -S "$ARM_LIB" | grep -Eq '\.debug_|\.zdebug_'; then
  echo "ARM64 library contains debug sections" >&2
  exit 24
fi
if readelf -S "$X86_LIB" | grep -Eq '\.debug_|\.zdebug_'; then
  echo "x86_64 library contains debug sections" >&2
  exit 25
fi

echo "== JNI symbol boundary =="
readelf -Ws "$ARM_LIB" | grep -q 'Java_dev_altru_safetyprotocol_android_SafetyProtocolNative_nativeAbiVersion'
readelf -Ws "$ARM_LIB" | grep -q 'Java_dev_altru_safetyprotocol_android_SafetyProtocolNative_nativeEvaluateConnectivity'

echo "== AAR native contents =="
AAR="android-adapter/build/outputs/aar/android-adapter-release.aar"
test -f "$AAR"
unzip -l "$AAR" | grep -q 'jni/arm64-v8a/libsafetyprotocol.so'
unzip -l "$AAR" | grep -q 'jni/x86_64/libsafetyprotocol.so'

echo "== Android permission boundary =="
manifest="android-adapter/src/main/AndroidManifest.xml"
grep -Fq 'android.permission.ACCESS_NETWORK_STATE' "$manifest"
if grep -Eq 'ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|NEARBY_WIFI_DEVICES' "$manifest"; then
  echo "Unexpected location/nearby permission" >&2
  exit 20
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

echo "== Diff hygiene =="
git diff --check

echo "Frequency sweep PASS"
