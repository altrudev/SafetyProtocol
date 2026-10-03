package dev.altru.safetyprotocol.android

import java.util.concurrent.atomic.AtomicBoolean

internal class TransportWriteClosedException :
    IllegalStateException("Transport writer is permanently closed for writes")

internal class ProtectedSessionCancelableTransportWriter internal constructor(
    private val channel: FramedTransportChannel,
    private val abortTransport: () -> Unit,
) : CancelableTransportWriter {
    constructor(session: ProtectedTransportSession) : this(
        channel = session.openFramedChannel(),
        abortTransport = session::close,
    )

    private val closedForWrites = AtomicBoolean(false)

    override fun prepare(
        frame: TransportFrame,
        permit: ForwardingExecutionPermit,
    ): CancelableTransportWrite {
        if (closedForWrites.get()) {
            throw TransportWriteClosedException()
        }

        val snapshot = TransportFrame(
            type = frame.type,
            sequence = frame.sequence,
            payload = frame.payload.copyOf(),
        )

        return object : CancelableTransportWrite {
            private val started = AtomicBoolean(false)

            override fun run() {
                check(started.compareAndSet(false, true)) {
                    "Prepared transport write may run only once"
                }
                if (closedForWrites.get()) {
                    throw TransportWriteClosedException()
                }
                channel.write(snapshot)
            }

            override fun cancel() {
                if (closedForWrites.compareAndSet(false, true)) {
                    abortTransport()
                }
            }
        }
    }
}
