# SafetyProtocol Bounded Execution Permit v0.11

Status: bounded, single-use permit and in-memory privacy-minimized execution receipt. Real network forwarding remains disabled.

## Purpose

v0.11 separates an eligible forwarding decision from the later test-sink handoff using an explicit permit.

A permit is issued only after the existing ForwardingGate approves the exact copied DATA frame under the stable v0.10 context/runtime revision boundary.

## Permit binding

Each permit is bound to:

- one issuing PermitForwardingExecutor instance
- one immutable copied DATA frame
- one contextRevision/runtimeRevision pair
- one issuance time
- one expiry time
- one bounded write budget
- one local permit ID

The original caller cannot replace or mutate the frame carried by the permit after issuance.

Permits are not bearer tokens across executors. A different executor cannot consume a permit.

## Bounds

Current hard ceilings:

- permit TTL: 1000 ms
- cooperative test-sink write budget: 250 ms
- write budget must not exceed permit TTL

Expiry is fail-closed at the exact boundary: now >= expiresAtMs is expired.

Clock regression is fail-closed and terminal for the permit.

## Single-use and cancellation

A permit has ISSUED, CANCELLED, or CONSUMED state.

A successful claim moves ISSUED to CONSUMED before any sink handoff. Revision mismatch, later gate denial, replay rejection, sink failure, or deadline failure cannot make that permit reusable.

Cancellation moves an unconsumed permit to CANCELLED. A cancelled permit cannot reach the sink.

## Revalidation at consumption

Permit consumption again enters the stable session context and live VPN runtime boundaries.

The executor rejects the permit if the composite revision differs from the issuance revision.

Even when the revision is unchanged, ForwardingGate is evaluated again with current monotonic time. This prevents stale liveness from being treated as current authority.

## Write failure and deadline

The sink used in v0.11 is test-only.

A sink exception represents an unknown or partial write and permanently poisons the executor.

If a cooperative test sink returns after its permit write deadline, the result is FAILED_CLOSED and the executor is poisoned.

v0.11 does not claim that a blocking real network write can be forcibly interrupted at the deadline. No real network sink exists in this slice.

## Receipt

Each terminal permit-consumption result carries an in-memory ForwardingExecutionReceipt with:

- permit ID
- composite execution revision
- frame sequence
- frame length
- terminal disposition
- terminal reason
- issue time
- terminal time

The receipt intentionally contains no packet payload, destination address, relay hostname, certificate/SPKI pin, SSID/BSSID, credential, or user/location identifier.

Receipts are not persisted by v0.11.

## Claim ceiling

v0.11 does not:

- forward TUN packets
- write to FramedTransportChannel, Socket, or OutputStream
- persist receipts
- provide cryptographically signed receipts
- provide hard cancellation of a blocked real network write
- enable forwardingActive=true
- provide persistent always-on/lockdown VPN enforcement

The next safe slice should define durable receipt integrity and bounded asynchronous transport cancellation before any production network sink is connected.
