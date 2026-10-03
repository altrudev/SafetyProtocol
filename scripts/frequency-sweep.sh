#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="full"
case "${1:-}" in
  "")
    ;;
  --preflight)
    MODE="preflight"
    ;;
  *)
    echo "Usage: $0 [--preflight]" >&2
    exit 64
    ;;
esac


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

if [[ "$MODE" == "preflight" ]]; then
    echo "== Android/JNI/enforcement preflight =="
    gradle :android-adapter:testDebugUnitTest
else
    echo "== Android full build/test gate =="
    gradle       :android-adapter:testDebugUnitTest       :android-adapter:lintDebug       :android-adapter:assembleRelease       :runtime-test-app:assembleDebug
fi

if [[ "$MODE" == "full" ]]; then
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
    jar tf "$tmp/classes.jar" | grep -q 'TransportFrameCodec.class'
    jar tf "$tmp/classes.jar" | grep -q 'TransportLivenessTracker.class'
    jar tf "$tmp/classes.jar" | grep -q 'TransportSessionReadiness.class'
    jar tf "$tmp/classes.jar" | grep -q 'ForwardingGate.class'
jar tf "$tmp/classes.jar" | grep -q 'PacketMetadataParser.class'
jar tf "$tmp/classes.jar" | grep -q 'PacketFlowPolicy.class'
jar tf "$tmp/classes.jar" | grep -q 'DestinationPolicy.class'
jar tf "$tmp/classes.jar" | grep -q 'DestinationRule.class'
jar tf "$tmp/classes.jar" | grep -q 'ForwardingExecutor.class'
jar tf "$tmp/classes.jar" | grep -q 'ForwardingExecutionSession.class'
jar tf "$tmp/classes.jar" | grep -q 'ForwardingExecutionRevision.class'
    rm -rf "$tmp"
    trap - EXIT
fi

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

if [[ "$MODE" == "full" ]]; then
    echo "== Cargo package =="
    cargo package --allow-dirty >/dev/null
    test "$(cargo tree --prefix none | wc -l)" -eq 1
fi



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

echo "== Framed transport/liveness v0.5 boundary =="
FRAME="android-adapter/src/main/java/dev/altru/safetyprotocol/android/TransportFrame.kt"
LIVE="android-adapter/src/main/java/dev/altru/safetyprotocol/android/TransportLiveness.kt"
READY="android-adapter/src/main/java/dev/altru/safetyprotocol/android/TransportSessionReadiness.kt"
grep -Fq 'const val MAX_PAYLOAD_BYTES = 64 * 1024' "$FRAME"
grep -Fq 'const val HEADER_BYTES = 20' "$FRAME"
grep -Fq 'private const val MAGIC = 0x53504631' "$FRAME"
grep -Fq 'SecureRandom()' "$LIVE"
grep -Fq 'MessageDigest.isEqual(expected.nonce, frame.payload)' "$LIVE"
grep -Fq 'establishment.authenticated && liveness.fresh' "$READY"
grep -Fq 'forwardingAuthorized = false' "$READY"
if grep -RInE 'protectedSessionAuthenticated[[:space:]]*=[[:space:]]*true' android-adapter/src/main/java; then
  echo "v0.5 must not promote framed liveness into VPN runtime readiness" >&2
  exit 35
fi
if grep -RInE 'tunnel(Input|Output)|tun(Input|Output)|write.*tunnel|write.*tun' android-adapter/src/main/java/dev/altru/safetyprotocol/android/TransportFrame.kt android-adapter/src/main/java/dev/altru/safetyprotocol/android/TransportLiveness.kt android-adapter/src/main/java/dev/altru/safetyprotocol/android/TransportSessionReadiness.kt; then
  echo "v0.5 framing/liveness layer must not implement TUN packet forwarding" >&2
  exit 36
fi

echo "== Constrained forwarding gate v0.6 boundary =="
GATE="android-adapter/src/main/java/dev/altru/safetyprotocol/android/ForwardingGate.kt"
RUNTIME="android-adapter/src/main/java/dev/altru/safetyprotocol/android/SafetyProtocolVpnRuntime.kt"
READINESS="android-adapter/src/main/java/dev/altru/safetyprotocol/android/TransportSessionReadiness.kt"
VPN_SERVICE="android-adapter/src/main/java/dev/altru/safetyprotocol/android/SafetyProtocolVpnService.kt"
grep -Fq 'runtime.transportReadiness' "$GATE"
grep -Fq 'readiness.isReadyAt(nowMs)' "$GATE"
grep -Fq 'CoreConnectivityAuthority.PROTECTED_TRANSPORT' "$GATE"
grep -Fq 'CoreDecisionReason.PROTECTED_TRANSPORT_ONLY' "$GATE"
grep -Fq 'MessageDigest.isEqual(authenticated.spkiSha256, candidate.spkiSha256)' "$GATE"
grep -Fq 'forwardingActive = false' "$GATE"
grep -Fq 'snapshot.transportReadiness?.isReadyAt(nowMs) == true' "$RUNTIME"
grep -Fq 'class TransportSessionReadiness internal constructor' "$READINESS"
grep -Fq 'validUntilMs' "$READINESS"
grep -Fq 'transportReadiness = null' "$VPN_SERVICE"
if grep -RInE 'forwardingActive[[:space:]]*=[[:space:]]*true' android-adapter/src/main/java; then
  echo "Forwarding execution must remain disabled in v0.6" >&2
  exit 37
fi
if grep -RInE 'tunnel(Output|Input).*write|tunnelInterface.*write|FileOutputStream.*tunnel' android-adapter/src/main/java; then
  echo "Unexpected TUN forwarding implementation found in v0.6" >&2
  exit 38
fi

echo "== Packet flow policy v0.7 boundary =="
PACKET="android-adapter/src/main/java/dev/altru/safetyprotocol/android/PacketMetadata.kt"
FLOW="android-adapter/src/main/java/dev/altru/safetyprotocol/android/PacketFlowPolicy.kt"
GATE="android-adapter/src/main/java/dev/altru/safetyprotocol/android/ForwardingGate.kt"
grep -Fq 'const val MAX_PACKET_BYTES = 65_535' "$PACKET"
grep -Fq 'PacketParseFailure.FRAGMENTED_PACKET' "$PACKET"
grep -Fq 'PacketParseFailure.UNSUPPORTED_EXTENSION_HEADER' "$PACKET"
grep -Fq 'DestinationScope.LOCAL_PRIVATE' "$FLOW"
grep -Fq 'DestinationScope.LINK_LOCAL' "$FLOW"
grep -Fq 'DestinationScope.LOOPBACK' "$FLOW"
grep -Fq 'DestinationScope.MULTICAST' "$FLOW"
grep -Fq 'PacketMetadataParser.parse(frame.payload)' "$GATE"
grep -Fq 'PacketFlowPolicy.evaluate(parsed.metadata)' "$GATE"
grep -Fq 'ForwardingGateReason.PACKET_PARSE_REJECTED' "$GATE"
grep -Fq 'ForwardingGateReason.DATA_FLOW_NOT_AUTHORIZED' "$GATE"
if grep -RInE 'forwardingActive[[:space:]]*=[[:space:]]*true' android-adapter/src/main/java; then
  echo "Forwarding execution must remain disabled in v0.7" >&2
  exit 39
fi
if grep -RInE 'FileOutputStream.*tunnel|tunnelInterface.*write|write.*tunnelInterface' android-adapter/src/main/java; then
  echo "Unexpected TUN output path found in v0.7" >&2
  exit 40
fi

echo "== Explicit destination policy v0.8 boundary =="
DEST="android-adapter/src/main/java/dev/altru/safetyprotocol/android/DestinationPolicy.kt"
GATE="android-adapter/src/main/java/dev/altru/safetyprotocol/android/ForwardingGate.kt"
grep -Fq 'class DestinationPolicy(' "$DEST"
grep -Fq 'DestinationPolicyReason.NO_MATCHING_ALLOW_RULE' "$DEST"
grep -Fq 'val bestPrefix = matches.maxOf' "$DEST"
grep -Fq 'val denyWins = strongest.any' "$DEST"
grep -Fq 'private val networkBytes: ByteArray' "$DEST"
grep -Fq 'destinationPolicy.evaluate(parsed.metadata.destination)' "$GATE"
grep -Fq 'ForwardingGateReason.DESTINATION_POLICY_NOT_AUTHORIZED' "$GATE"
if grep -RInE 'Log\.[vdiew].*(addressBytes|destination)|println\(.*(addressBytes|destination)' android-adapter/src/main/java; then
  echo "Exact destination logging surface found" >&2
  exit 41
fi
if grep -RInE 'forwardingActive[[:space:]]*=[[:space:]]*true' android-adapter/src/main/java; then
  echo "Forwarding execution must remain disabled in v0.8" >&2
  exit 42
fi

echo "== Loopback executor v0.9 boundary =="
EXECUTOR="android-adapter/src/main/java/dev/altru/safetyprotocol/android/ForwardingExecutor.kt"
MAIN_SRC="android-adapter/src/main/java"
grep -Fq 'payload = frame.payload.copyOf()' "$EXECUTOR"
grep -Fq 'SafetyProtocolVpnRuntime.withStableSnapshot' "$EXECUTOR"
grep -Fq 'ForwardingGate.evaluate(' "$EXECUTOR"
grep -Fq 'System.nanoTime() / 1_000_000L' "$EXECUTOR"
grep -Fq 'exactFrame.sequence <= last' "$EXECUTOR"
grep -Fq 'poisoned = true' "$EXECUTOR"
grep -Fq 'ForwardingExecutionReason.EXECUTOR_POISONED' "$EXECUTOR"
if grep -RIn 'ForwardingExecutor(' "$MAIN_SRC" --exclude='ForwardingExecutor.kt'; then
  echo "Production ForwardingExecutor call site found before v0.9 promotion boundary" >&2
  exit 43
fi
if grep -RIn ': ForwardingFrameSink' "$MAIN_SRC" --exclude='ForwardingExecutor.kt'; then
  echo "Production ForwardingFrameSink implementation found before v0.9 promotion boundary" >&2
  exit 44
fi
if grep -RInE 'forwardingActive[[:space:]]*=[[:space:]]*true' "$MAIN_SRC"; then
  echo "Real forwarding activation must remain disabled in v0.9" >&2
  exit 45
fi

echo "== Session execution revision v0.10 boundary =="
SESSION="android-adapter/src/main/java/dev/altru/safetyprotocol/android/ForwardingExecutionSession.kt"
RUNTIME="android-adapter/src/main/java/dev/altru/safetyprotocol/android/SafetyProtocolVpnRuntime.kt"
grep -Fq 'data class ForwardingExecutionRevision' "$SESSION"
grep -Fq 'Math.addExact(revision, 1L)' "$SESSION"
grep -Fq 'spkiSha256.copyOf()' "$SESSION"
grep -Fq 'withStableContext' "$SESSION"
grep -Fq 'executionLeaseActive' "$SESSION"
grep -Fq 'Execution context cannot mutate during an active execution lease' "$SESSION"
grep -Fq 'currentRevision' "$RUNTIME"
grep -Fq 'Math.addExact(currentRevision, 1L)' "$RUNTIME"
grep -Fq 'withStableSnapshot' "$RUNTIME"
grep -Fq 'executionLeaseActive' "$RUNTIME"
grep -Fq 'VPN runtime cannot mutate during an active execution lease' "$RUNTIME"
grep -Fq 'session.withStableContext' "$EXECUTOR"
grep -Fq 'SafetyProtocolVpnRuntime.withStableSnapshot' "$EXECUTOR"
grep -Fq 'sink.write(exactFrame, revision)' "$EXECUTOR"
grep -Fq 'executionRevision = revision' "$EXECUTOR"
grep -Fq 'contextRevision = context.revision' "$EXECUTOR"
grep -Fq 'runtimeRevision = runtimeRevision' "$EXECUTOR"
if grep -RIn ': ForwardingFrameSink' "$MAIN_SRC" --exclude='ForwardingExecutor.kt'; then
  echo "Production forwarding sink implementation found in v0.10" >&2
  exit 46
fi
if grep -RInE 'FramedTransportChannel.*ForwardingFrameSink|Socket.*ForwardingFrameSink|OutputStream.*ForwardingFrameSink' "$MAIN_SRC"; then
  echo "Real network sink introduced before v0.10 claim ceiling" >&2
  exit 47
fi

echo "== Diff hygiene =="
git diff --check

RUNTIME_STATUS="NOT VERIFIED"
if [[ "$MODE" == "full" ]]; then
    if [[ "${SAFETYPROTOCOL_RUNTIME_DEVICE:-0}" == "1" ]]; then
        echo "== Real Android runtime smoke =="
        scripts/android-vpn-runtime-smoke.sh
        RUNTIME_STATUS="PASS"
    else
        echo "== Real Android runtime smoke == NOT VERIFIED (set SAFETYPROTOCOL_RUNTIME_DEVICE=1)"
    fi
    echo "Frequency full sweep PASS"
    echo "Frequency real-device VPN runtime: ${RUNTIME_STATUS}"
else
    echo "Frequency preflight PASS"
    echo "Promotion/release gates intentionally deferred to full sweep"
fi
