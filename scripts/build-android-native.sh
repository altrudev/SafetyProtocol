#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?usage: build-android-native.sh OUT_DIR}"
: "${ANDROID_SDK_ROOT:=$HOME/.local/android-sdk}"
NDK_VERSION="30.0.16248370"
NDK="$ANDROID_SDK_ROOT/ndk/$NDK_VERSION"
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
API=26

test -x "$TOOLCHAIN/aarch64-linux-android${API}-clang"
test -x "$TOOLCHAIN/x86_64-linux-android${API}-clang"

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/aarch64-linux-android${API}-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$TOOLCHAIN/x86_64-linux-android${API}-clang"

cd "$ROOT"
cargo build --release --target aarch64-linux-android
cargo build --release --target x86_64-linux-android

rm -rf "$OUT"
mkdir -p "$OUT/arm64-v8a" "$OUT/x86_64"
cp target/aarch64-linux-android/release/libsafetyprotocol.so "$OUT/arm64-v8a/libsafetyprotocol.so"
cp target/x86_64-linux-android/release/libsafetyprotocol.so "$OUT/x86_64/libsafetyprotocol.so"
