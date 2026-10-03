package dev.altru.safetyprotocol.android

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BoundedAsyncPermitSinkTest {
    private val endpoint = ProtectedTransportEndpoint.fromHexPin(
        "relay.example", 443, "11".repeat(32),
    )
    private val policy = CoreConnectivityDecision(
        authority = CoreConnectivityAuthority.PROTECTED_TRANSPORT,
        reason = CoreDecisionReason.PROTECTED_TRANSPORT_ONLY,
        effective = CoreAuthority(
            transport = true,
            read = false,
            write = false,
            execute = false,
            localNetwork = false,
            directDns = false,
            credentialUse = false,
            dataEgress = true,
        ),
        protectedTunnelRequired = true,
    )
    private val destinations = DestinationPolicy(
        listOf(DestinationRule.allow("8.8.8.0/24")),
    )

    @After
    fun resetRuntime() {
        SafetyProtocolVpnRuntime.reset()
    }

    @Test
    fun completedAsyncWriteExecutes() {
        installRuntime()
        val writer = ImmediateWriter()
        val sink = BoundedAsyncPermitSink(writer)
        val executor = executor(sink)

        val permit = executor.issuePermit(frame(), ttlMs = 200, writeBudgetMs = 100)!!
        val result = executor.consume(permit)

        assertEquals(ForwardingExecutionDisposition.EXECUTED, result.disposition)
        assertEquals(1, writer.runs)
    }

    @Test
    fun blockedWriteIsCancelledAtDeadlineAndPoisonsExecutor() {
        installRuntime()
        val writer = BlockingCancellableWriter()
        val sink = BoundedAsyncPermitSink(writer, cancellationGraceMs = 50)
        val executor = executor(sink)

        val permit = executor.issuePermit(frame(), ttlMs = 250, writeBudgetMs = 40)!!
        val startedAt = System.nanoTime()
        val result = executor.consume(permit)
        val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)

        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, result.disposition)
        assertEquals(ForwardingExecutionReason.WRITE_DEADLINE_EXCEEDED, result.reason)
        assertTrue(writer.cancelled.get())
        assertTrue(elapsedMs < 500)
        assertNull(executor.issuePermit(frame(11), ttlMs = 200, writeBudgetMs = 50))
    }

    @Test
    fun cancellationThatDoesNotStopWorkerStillReturnsBounded() {
        installRuntime()
        val writer = CancellationIgnoringWriter()
        val sink = BoundedAsyncPermitSink(writer, cancellationGraceMs = 30)
        val executor = executor(sink)

        val permit = executor.issuePermit(frame(), ttlMs = 200, writeBudgetMs = 30)!!
        val startedAt = System.nanoTime()
        val result = executor.consume(permit)
        val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)

        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, result.disposition)
        assertEquals(ForwardingExecutionReason.WRITE_CANCELLATION_UNCONFIRMED, result.reason)
        assertTrue(writer.cancelCalled.get())
        assertTrue(elapsedMs < 500)
        writer.release.countDown()
    }

    @Test
    fun prepareFailureNeverStartsWorker() {
        installRuntime()
        val sink = BoundedAsyncPermitSink(object : CancelableTransportWriter {
            override fun prepare(frame: TransportFrame, permit: ForwardingExecutionPermit): CancelableTransportWrite {
                throw IllegalStateException("prepare failed")
            }
        })
        val executor = executor(sink)

        val permit = executor.issuePermit(frame(), ttlMs = 200, writeBudgetMs = 50)!!
        val result = executor.consume(permit)

        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, result.disposition)
        assertEquals(ForwardingExecutionReason.WRITE_FAILED, result.reason)
    }

    private fun executor(sink: ForwardingPermitSink): PermitForwardingExecutor =
        PermitForwardingExecutor(
            session = ForwardingExecutionSession(policy, endpoint, endpoint, destinations),
            sink = sink,
            receiptStore = ForwardingReceiptStore { },
        )

    private fun installRuntime() {
        SafetyProtocolVpnRuntime.update {
            it.copy(
                serviceRunning = true,
                captureEstablished = true,
                osVpnTransportObserved = true,
                transportReadiness = TransportSessionReadiness(
                    authenticatedEstablishment = true,
                    freshLiveness = true,
                    protectedSessionReady = true,
                    validUntilMs = System.nanoTime() / 1_000_000L + 10_000,
                    forwardingAuthorized = false,
                ),
            )
        }
    }

    private fun frame(sequence: Long = 10) =
        TransportFrame(TransportFrameType.DATA, sequence, publicIpv4TcpPacket())

    private class ImmediateWriter : CancelableTransportWriter {
        var runs = 0
        override fun prepare(frame: TransportFrame, permit: ForwardingExecutionPermit) =
            object : CancelableTransportWrite {
                override fun run() {
                    runs += 1
                }
                override fun cancel() = Unit
            }
    }

    private class BlockingCancellableWriter : CancelableTransportWriter {
        val cancelled = AtomicBoolean(false)
        override fun prepare(frame: TransportFrame, permit: ForwardingExecutionPermit) =
            object : CancelableTransportWrite {
                private val release = CountDownLatch(1)
                override fun run() {
                    release.await()
                }
                override fun cancel() {
                    cancelled.set(true)
                    release.countDown()
                }
            }
    }

    private class CancellationIgnoringWriter : CancelableTransportWriter {
        val cancelCalled = AtomicBoolean(false)
        val release = CountDownLatch(1)
        override fun prepare(frame: TransportFrame, permit: ForwardingExecutionPermit) =
            object : CancelableTransportWrite {
                override fun run() {
                    while (release.count > 0) {
                        try {
                            release.await(10, TimeUnit.MILLISECONDS)
                        } catch (_: InterruptedException) {
                            // Intentionally ignore interruption for bounded-return testing.
                        }
                    }
                }
                override fun cancel() {
                    cancelCalled.set(true)
                }
            }
    }

    private fun publicIpv4TcpPacket(): ByteArray {
        val packet = ByteArray(40)
        packet[0] = 0x45
        packet[2] = 0
        packet[3] = 40
        packet[8] = 64
        packet[9] = 6
        packet[12] = 10
        packet[13] = 0
        packet[14] = 0
        packet[15] = 2
        packet[16] = 8
        packet[17] = 8
        packet[18] = 8
        packet[19] = 8
        packet[20] = 0x30
        packet[21] = 0x39
        packet[22] = 1
        packet[23] = (443 and 0xff).toByte()
        packet[32] = 0x50
        return packet
    }
}
