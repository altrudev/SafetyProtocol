# SafetyProtocol Loopback Forwarding Executor v0.9

Status: internal execution-gating primitive only. No production forwarding call site exists.

## Purpose

v0.9 proves that the existing forwarding-eligibility decision can control a writer without creating a parallel authorization path.

The executor is internal to the Android adapter and is not wired into SafetyProtocolVpnService or the protected transport.

## Execution sequence

For each candidate DATA frame the executor:

1. copies the frame payload to create an execution snapshot
2. reads the live SafetyProtocolVpnRuntime snapshot itself
3. obtains the current monotonic time from its own clock
4. calls the existing ForwardingGate.evaluate function on that exact frame
5. writes only when the gate returns ELIGIBLE
6. rejects a sequence that is equal to or older than the last successfully executed sequence
7. advances the sequence only after a successful write

DROP never reaches the writer.

## Failure behavior

Unexpected gate/clock evaluation failure returns FAILED_CLOSED.

A writer exception returns FAILED_CLOSED and permanently poisons that executor instance. A poisoned executor refuses all later writes. This avoids retrying after an unknown partial-write state.

Replay or out-of-order frames are dropped without reaching the writer.

## Runtime authority

The executor does not accept a caller-supplied VPN runtime snapshot and does not accept an arbitrary eligibility callback. It calls SafetyProtocolVpnRuntime.snapshot and ForwardingGate.evaluate directly.

The monotonic production clock is System.nanoTime-based. Test code may inject a deterministic clock.

## Current explicit inputs

The Rust policy decision, authenticated relay endpoint, candidate relay endpoint, and DestinationPolicy are still explicit execution inputs because those values do not yet have a single centralized runtime owner.

v0.9 proves that changes to those inputs are honored at execution time, but it does not claim global atomicity if another thread changes an external policy/session source during a writer call.

## No production data path

No production class instantiates ForwardingExecutor in v0.9. No production ForwardingFrameSink implementation exists.

The VPN packet loop therefore remains drop-only.

## Claim ceiling

v0.9 does not:

- forward real TUN packets
- write to FramedTransportChannel
- write to a network socket
- guarantee rollback after a partial external write
- atomically bind policy/session drift occurring during an already-started writer call
- prove v0.9 execution on a physical Android device

The next slice should introduce a session-owned execution context/revision and a test transport sink before any real TUN-to-network connection is made.
