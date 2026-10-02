#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

: "${ANDROID_SDK_ROOT:=$HOME/.local/android-sdk}"
export ANDROID_SDK_ROOT
export ANDROID_HOME="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"

echo "== Rust core =="
cargo fmt --check
cargo test --quiet
cargo clippy --all-targets --all-features -- -D warnings

echo "== Android unit tests =="
gradle :android-adapter:testDebugUnitTest

echo "== Android lint =="
gradle :android-adapter:lintDebug

echo "== Android release AAR =="
gradle :android-adapter:assembleRelease

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

echo "== Secret / endpoint scan =="
if grep -RInE 'api[_-]?key|access[_-]?token|password|secret|https?://' android-adapter/src/main/java android-adapter/src/test/java; then
  echo "Sensitive indicator found" >&2
  exit 22
fi

echo "== Diff hygiene =="
git diff --check

echo "Frequency sweep PASS"
