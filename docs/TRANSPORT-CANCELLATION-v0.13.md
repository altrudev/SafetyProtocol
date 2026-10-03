# SafetyProtocol Transport Cancellation Proof v0.13

Status: cancellation-safe application-level framed transport writer. No production forwarding path is connected.

## Purpose

v0.12 bounded the caller after a write deadline, but its cancellation callback could itself block. It also had no transport-specific writer whose cancellation permanently closed the authenticated transport surface.

v0.13 closes both gaps.

## Protected-session cancelable writer

ProtectedSessionCancelableTransportWriter is the only allowlisted production implementation of CancelableTransportWriter.

It can be constructed from an authenticated ProtectedTransportSession. That constructor:

- opens the session's FramedTransportChannel
- binds cancellation to ProtectedTransportSession.close()
- permanently marks the writer closed before invoking transport abort

Each prepared write owns an immutable copy of the frame payload.

Once cancellation begins, the writer is permanently closed for future prepares. A prepared operation that has not started cannot begin emission after the writer is closed.

## Bounded cancellation callback

BoundedAsyncPermitSink no longer invokes cancel() on the policy thread.

At write deadline it:

1. starts cancellation on a daemon cancellation worker
2. interrupts the write worker
3. uses one cancellation-grace deadline for both cancellation return and write-worker termination
4. requires cancel() to return without failure
5. requires the write worker to terminate inside the remaining grace

If either condition is not established, the outcome is WRITE_CANCELLATION_UNCONFIRMED and the permit executor poisons itself.

Cancellation grace remains hard-capped at 100 ms.

## Confirmed-cancellation meaning

Within v0.13, confirmed cancellation means:

- the cancellation callback returned successfully
- the prepared write worker terminated
- the writer is permanently closed for later application writes

Tests verify that after this point the application-level byte-attempt count does not increase.

## Critical claim ceiling

v0.13 does **not** claim that no bytes already accepted by TLS, the kernel, NIC, or another lower-layer buffer can drain onto the wire after socket close returns.

Therefore the verified statement is:

> After confirmed v0.13 cancellation, this writer cannot initiate any later application-level FramedTransportChannel emission.

It is not:

> No later physical/network byte can appear on the wire.

A wire-level claim would require a lower-level transport design with stronger cancellation/acknowledgement semantics.

## Adversarial cases

Tests cover:

- immutable frame ownership
- cancellation before run prevents emission
- cancellation permanently prevents reuse
- idempotent cancellation / one abort
- blocked framed output released by transport abort
- no later application emission after confirmed cancellation
- cancellation callback that blocks
- cancellation callback that throws
- worker that ignores interruption/cancellation

## Production boundary

v0.13 still has:

- no production PermitForwardingExecutor call site
- no production BoundedAsyncPermitSink call site
- no production ProtectedSessionCancelableTransportWriter call site
- no TUN-to-FramedTransportChannel path
- no forwardingActive=true path

The next safe step is a controlled emulator-only end-to-end transport experiment, still without general device traffic forwarding.
