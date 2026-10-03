# SafetyProtocol Session Execution Revision v0.10

Status: session-owned execution context and atomic test-sink boundary. Real forwarding remains disabled.

## Purpose

v0.10 binds policy, relay identity, destination policy, and live VPN runtime state to the execution attempt that reaches a test sink.

It closes the v0.9 drift window between gate evaluation and writer invocation without introducing a real network sink.

## Composite execution revision

Every execution evaluated inside the stable boundary has a ForwardingExecutionRevision composed of:

- contextRevision: session-owned policy/relay/destination revision
- runtimeRevision: live SafetyProtocolVpnRuntime revision

Successful writes, gate-denied drops, replay drops, evaluation failures after the stable boundary is entered, and writer failures carry revision evidence when available.

An already-poisoned executor has no new execution revision because it refuses the attempt before entering a stable execution boundary.

## Session-owned context

ForwardingExecutionSession owns:

- CoreConnectivityDecision
- authenticated relay endpoint
- candidate relay endpoint
- DestinationPolicy

Every committed context mutation increments contextRevision using checked arithmetic.

Relay SPKI pin byte arrays are defensively copied both when entering the session and when creating an execution snapshot.

## VPN runtime revision

SafetyProtocolVpnRuntime now increments runtimeRevision on every committed runtime mutation, including protected-session update, protected-session clear, general runtime update, and reset.

Runtime mutation and revision advancement occur under the same synchronized owner.

## Stable execution lease

ForwardingExecutor enters the session stable-context lease and then the VPN runtime stable-snapshot lease.

Gate evaluation and the test sink write occur while both leases remain active.

Concurrent context/runtime updates therefore wait until the execution critical section completes.

Because synchronized monitors are reentrant, both owners also maintain an explicit executionLeaseActive guard. Same-thread mutation attempts from inside a sink are rejected rather than silently changing the supposedly stable state.

A writer exception, including one caused by a forbidden reentrant mutation, permanently poisons the executor as in v0.9.

## Test transport sink

v0.10 uses only test-source ForwardingFrameSink implementations. The sink receives the exact frame snapshot plus the composite execution revision.

No production ForwardingFrameSink implementation exists and no production ForwardingExecutor call site exists.

## Claim ceiling

v0.10 does not:

- forward TUN packets
- write to FramedTransportChannel or a socket
- hold these synchronization leases around a real potentially blocking network writer
- provide a bounded real-writer deadline/cancellation protocol
- persist execution revisions as durable receipts
- provide persistent always-on/lockdown VPN enforcement

The next slice should convert the composite revision into a bounded execution permit/receipt and test transport handoff without exposing a real network sink until cancellation, timeout, and partial-write behavior are specified.
