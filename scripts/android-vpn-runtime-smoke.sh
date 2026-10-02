#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

: "${ANDROID_SDK_ROOT:=$HOME/.local/android-sdk}"
ADB="$ANDROID_SDK_ROOT/platform-tools/adb"
PKG="dev.altru.safetyprotocol.runtime"
APK="runtime-test-app/build/outputs/apk/debug/runtime-test-app-debug.apk"
PORT="${SAFETYPROTOCOL_PROBE_PORT:-18080}"
HOST_SERVER_STARTED=0
SERVER_PID=""

cleanup() {
    "$ADB" shell am force-stop "$PKG" >/dev/null 2>&1 || true
    if [[ "$HOST_SERVER_STARTED" == 1 && -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if [[ -n "${ANDROID_SERIAL:-}" ]]; then
    export ANDROID_SERIAL
fi

devices="$($ADB devices | awk 'NR>1 && $2=="device" {print $1}')"
[[ $(printf '%s\n' "$devices" | sed '/^$/d' | wc -l) -eq 1 ]] || {
    echo "Runtime smoke requires exactly one connected Android device/emulator" >&2
    exit 40
}

if ! ss -ltn | grep -q ":${PORT} "; then
    python3 -m http.server "$PORT" --bind 0.0.0.0 >/tmp/safetyprotocol-probe-server.log 2>&1 &
    SERVER_PID=$!
    HOST_SERVER_STARTED=1
    sleep 1
fi

gradle :runtime-test-app:assembleDebug
test -f "$APK"

$ADB install -r "$APK" >/dev/null

# Emulator/test automation only. Production applications must use VpnService.prepare()
# and normal Android user consent/system configuration.
$ADB shell appops set "$PKG" ACTIVATE_VPN allow
$ADB logcat -c
$ADB shell am force-stop "$PKG"
$ADB shell am start -n "$PKG/.RuntimeTestActivity" >/dev/null
sleep 12

log="$($ADB logcat -d -s SafetyProtocolRuntime:I '*:S')"
printf '%s\n' "$log"
result="$(printf '%s\n' "$log" | grep 'RUNTIME_RESULT' | tail -1)"

[[ "$result" == *"pre=true"* ]]
[[ "$result" == *"capture=true"* ]]
[[ "$result" == *"osVpn=true"* ]]
[[ "$result" == *"sessionFailClosed=true"* ]]
[[ "$result" == *"post=false"* ]]

connectivity="$($ADB shell dumpsys connectivity)"
printf '%s\n' "$connectivity" | grep -m1 -q 'VPN CONNECTED extra: VPN:dev.altru.safetyprotocol.runtime'
printf '%s\n' "$connectivity" | grep -m1 -q 'sessionId=SafetyProtocol, bypassable=false'
printf '%s\n' "$connectivity" | grep -m1 -q 'InterfaceName: tun0'
printf '%s\n' "$connectivity" | grep -m1 -q '0.0.0.0/0 -> 0.0.0.0 tun0'
printf '%s\n' "$connectivity" | grep -m1 -q '::/0 -> :: tun0'

echo "Android VPN runtime smoke PASS"
