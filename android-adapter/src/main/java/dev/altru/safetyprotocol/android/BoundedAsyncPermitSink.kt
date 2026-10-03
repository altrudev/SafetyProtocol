package dev.altru.safetyprotocol.android

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

internal fun interface CancelableTransportWriter {
    fun prepare(
        frame: TransportFrame,
        permit: ForwardingExecutionPermit,
    ): CancelableTransportWrite
}

internal interface CancelableTransportWrite {
    fun run()
    fun cancel()
}

internal class AsyncWriteDeadlineExceededException :
    IllegalStateException("Asynchronous transport write exceeded permit deadline")

internal class AsyncWriteCancellationUnconfirmedException :
    IllegalStateException("Asynchronous transport write did not stop within cancellation grace")

internal class BoundedAsyncPermitSink(
    private val writer: CancelableTransportWriter,
    private val cancellationGraceMs: Long = 50L,
) : ForwardingPermitSink {
    companion object {
        const val MAX_CANCELLATION_GRACE_MS = 100L
    }

    init {
        require(cancellationGraceMs in 1..MAX_CANCELLATION_GRACE_MS)
    }

    override fun write(
        frame: TransportFrame,
        permit: ForwardingExecutionPermit,
    ) {
        val operation = writer.prepare(
            TransportFrame(frame.type, frame.sequence, frame.payload.copyOf()),
            permit,
        )
        val finished = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>(null)

        val worker = Thread(
            {
                try {
                    operation.run()
                } catch (t: Throwable) {
                    failure.set(t)
                } finally {
                    finished.countDown()
                }
            },
            "SafetyProtocol-v0.12-bounded-write",
        ).apply {
            isDaemon = true
            start()
        }

        if (!finished.await(permit.writeBudgetMs, TimeUnit.MILLISECONDS)) {
            try {
                operation.cancel()
            } catch (_: Throwable) {
                // A failed cancellation request is represented by the bounded unconfirmed outcome.
            }
            worker.interrupt()

            if (!finished.await(cancellationGraceMs, TimeUnit.MILLISECONDS)) {
                throw AsyncWriteCancellationUnconfirmedException()
            }
            throw AsyncWriteDeadlineExceededException()
        }

        failure.get()?.let { throw it }
    }
}
