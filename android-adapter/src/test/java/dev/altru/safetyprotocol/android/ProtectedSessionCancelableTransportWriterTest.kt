package dev.altru.safetyprotocol.android

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectedSessionCancelableTransportWriterTest {
    @Test
    fun successfulWriteUsesImmutablePreparedFrame() {
        val output = ByteArrayOutputStream()
        val channel = FramedTransportChannel(ByteArrayInputStream(ByteArray(0)), output)
        val writer = ProtectedSessionCancelableTransportWriter(channel) { }
        val payload = byteArrayOf(1, 2, 3)
        val frame = TransportFrame(TransportFrameType.DATA, 7, payload)
        val operation = writer.prepare(frame, permit())
        payload[0] = 99

        operation.run()

        val decoded = TransportFrameCodec.read(ByteArrayInputStream(output.toByteArray()))
        assertEquals(7L, decoded.sequence)
        assertArrayEquals(byteArrayOf(1, 2, 3), decoded.payload)
    }

    @Test
    fun cancellationBeforeRunPermanentlyPreventsEmission() {
        val output = ByteArrayOutputStream()
        val channel = FramedTransportChannel(ByteArrayInputStream(ByteArray(0)), output)
        val abortCalled = AtomicBoolean(false)
        val writer = ProtectedSessionCancelableTransportWriter(channel) {
            abortCalled.set(true)
        }
        val operation = writer.prepare(frame(), permit())

        operation.cancel()

        var failed = false
        try {
            operation.run()
        } catch (_: TransportWriteClosedException) {
            failed = true
        }

        assertTrue(failed)
        assertTrue(abortCalled.get())
        assertEquals(0, output.size())

        var prepareFailed = false
        try {
            writer.prepare(frame(12), permit(2))
        } catch (_: TransportWriteClosedException) {
            prepareFailed = true
        }
        assertTrue(prepareFailed)
    }

    @Test
    fun confirmedCancellationLeavesNoLaterApplicationEmission() {
        val output = AbortableBlockingOutputStream()
        val channel = FramedTransportChannel(ByteArrayInputStream(ByteArray(0)), output)
        val writer = ProtectedSessionCancelableTransportWriter(channel, output::abort)
        val sink = BoundedAsyncPermitSink(writer, cancellationGraceMs = 80)
        val permit = permit(writeBudgetMs = 25)

        var deadline = false
        try {
            sink.write(frame(), permit)
        } catch (_: AsyncWriteDeadlineExceededException) {
            deadline = true
        }

        assertTrue(deadline)
        assertTrue(output.abortCalled.get())
        assertTrue(output.writerExited.await(100, TimeUnit.MILLISECONDS))
        val bytesAtConfirmation = output.bytesAttempted
        Thread.sleep(40)
        assertEquals(bytesAtConfirmation, output.bytesAttempted)
        assertFalse(output.emissionAfterAbort.get())
    }

    @Test
    fun cancellationIsIdempotentAndAbortRunsOnce() {
        val output = ByteArrayOutputStream()
        val channel = FramedTransportChannel(ByteArrayInputStream(ByteArray(0)), output)
        var aborts = 0
        val writer = ProtectedSessionCancelableTransportWriter(channel) { aborts += 1 }
        val operation = writer.prepare(frame(), permit())

        operation.cancel()
        operation.cancel()

        assertEquals(1, aborts)
    }

    private fun frame(sequence: Long = 11) =
        TransportFrame(TransportFrameType.DATA, sequence, byteArrayOf(9, 8, 7))

    private fun permit(
        id: Long = 1,
        writeBudgetMs: Long = 25,
    ) = ForwardingExecutionPermit(
        permitId = id,
        revision = ForwardingExecutionRevision(1, 1),
        issuedAtMs = 100,
        expiresAtMs = 1_000,
        writeBudgetMs = writeBudgetMs,
        ownerToken = Any(),
        frame = frame(),
    )

    private class AbortableBlockingOutputStream : OutputStream() {
        val abortCalled = AtomicBoolean(false)
        val emissionAfterAbort = AtomicBoolean(false)
        val writerExited = CountDownLatch(1)
        private val release = CountDownLatch(1)

        @Volatile
        var bytesAttempted: Int = 0
            private set

        override fun write(value: Int) {
            if (abortCalled.get()) {
                emissionAfterAbort.set(true)
                throw IOException("transport aborted")
            }
            bytesAttempted += 1
            try {
                release.await()
            } catch (_: InterruptedException) {
                // Keep waiting until the transport abort is confirmed.
                while (!abortCalled.get()) {
                    try {
                        release.await(5, TimeUnit.MILLISECONDS)
                    } catch (_: InterruptedException) {
                        // Intentionally ignore interruption until abort.
                    }
                }
            } finally {
                writerExited.countDown()
            }
            throw IOException("transport aborted")
        }

        fun abort() {
            abortCalled.set(true)
            release.countDown()
        }
    }
}
