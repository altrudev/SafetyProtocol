# SafetyProtocol Durable Receipts and Bounded Async Handoff v0.12

Status: local receipt persistence plus test-only bounded asynchronous handoff. Real TUN-to-network forwarding remains disabled.

## DDC/Frequency boundary

v0.12 deliberately replaces the v0.11 rule that prohibited every production ForwardingPermitSink implementation.

The only allowlisted implementation is BoundedAsyncPermitSink. Frequency rejects any other production ForwardingPermitSink implementation, any production BoundedAsyncPermitSink call site, and any production CancelableTransportWriter implementation.

Existing ProtectedTransport networking code is not treated as a v0.12 binding merely because it contains sockets. The v0.12 adapter itself must remain free of Socket, OutputStream, FramedTransportChannel, URLConnection, HTTP, or other real-network primitives.

## Durable receipt store

PermitForwardingExecutor now requires a ForwardingReceiptStore.

Every terminal permit-consumption receipt is offered to that store. Persistence outcome is reported separately from the action outcome:

- PERSISTED: the store accepted the receipt
- FAILED: persistence failed
- NOT_ATTEMPTED: no terminal permit receipt was attempted

If persistence fails after an action already executed, the result does not rewrite history by claiming the action was dropped. The original action disposition/reason remains intact, receiptPersistence becomes FAILED, and the executor is poisoned so no later permit can be issued.

## Hash-chained local journal

HashChainedReceiptJournal is a ForwardingReceiptStore with:

- SHA-256 record chaining
- bounded record size
- fsync after each journal append
- a sibling anchor containing committed record count and last record hash
- fsynced anchor content and atomic-replace attempt
- verification before every append
- refusal to append to a corrupted or inconsistent chain
- whole-record suffix-truncation detection through the anchor

The journal has hard resource ceilings:

- maximum 4,096 records
- maximum 1,048,576 journal bytes
- maximum 4,096 bytes per encoded record

Reaching a ceiling fails closed rather than rotating or deleting evidence silently.

## Crash ordering

The journal record is fsynced before the anchor is advanced.

A crash between those operations can leave the journal one valid record ahead of the anchor. Reopen then fails closed with an anchor mismatch. v0.12 does not silently reconcile or discard that evidence.

The anchor replacement attempts an atomic move and falls back to replacement when the platform does not support it. v0.12 does not claim a separately fsynced parent-directory entry.

## Integrity claim ceiling

The hash chain plus local anchor detects accidental/local corruption, partial truncation, complete valid-suffix removal when the anchor survives, missing anchors, and anchor/journal mismatch.

It is not cryptographic authenticity against an attacker who can rewrite both the journal and the anchor. v0.12 does not use Android Keystore, signatures, remote witnesses, or an independently protected anchor.

## Bounded asynchronous handoff

BoundedAsyncPermitSink is a test-handoff adapter only.

It:

- copies the exact frame before preparing the operation
- runs the prepared operation on a daemon worker
- waits only for the permit write budget
- requests operation cancellation at deadline
- interrupts the worker
- waits only a bounded cancellation grace
- returns WRITE_DEADLINE_EXCEEDED when cancellation completes after deadline
- returns WRITE_CANCELLATION_UNCONFIRMED when the worker does not stop within the grace

Cancellation grace is hard-capped at 100 ms.

Either timeout result causes PermitForwardingExecutor to poison itself.

## Claim ceiling

v0.12 still does not:

- instantiate PermitForwardingExecutor from production code
- instantiate BoundedAsyncPermitSink from production code
- provide a production CancelableTransportWriter
- write TUN packets to a socket or FramedTransportChannel
- force-stop an arbitrary JVM thread
- guarantee that an unconfirmed background operation can no longer cause an external side effect
- cryptographically authenticate the local receipt journal
- enable forwardingActive=true

A real network writer must not be connected until its cancellation semantics can prove that an unconfirmed worker cannot continue transmitting after the caller has failed closed.
