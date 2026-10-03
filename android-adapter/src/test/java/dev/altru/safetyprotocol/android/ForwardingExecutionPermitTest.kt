package dev.altru.safetyprotocol.android

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ForwardingExecutionPermitTest {
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
    fun permitIsSingleUseAndProducesPrivacyMinimizedReceipt() {
        installRuntime()
        val clock = MutableClock(500)
        val sink = RecordingPermitSink()
        val executor = executor(sink, clock)

        val permit = executor.issuePermit(frame(), ttlMs = 100, writeBudgetMs = 20)
        assertNotNull(permit)

        val first = executor.consume(permit!!)
        val second = executor.consume(permit)

        assertEquals(ForwardingExecutionDisposition.EXECUTED, first.disposition)
        assertEquals(ForwardingExecutionReason.EXECUTED, first.reason)
        assertEquals(ForwardingExecutionReason.PERMIT_ALREADY_CONSUMED, second.reason)
        assertEquals(1, sink.frames.size)

        val receipt = first.receipt!!
        assertEquals(10L, receipt.frameSequence)
        assertEquals(40, receipt.frameLength)
        assertEquals(permit.revision, receipt.revision)
        val fieldNames = ForwardingExecutionReceipt::class.java.declaredFields.map { it.name }.toSet()
        assertFalse("destination" in fieldNames)
        assertFalse("payload" in fieldNames)
        assertFalse("relayHost" in fieldNames)
        assertFalse("spkiSha256" in fieldNames)
    }

    @Test
    fun expiredPermitNeverReachesSink() {
        installRuntime()
        val clock = MutableClock(500)
        val sink = RecordingPermitSink()
        val executor = executor(sink, clock)

        val permit = executor.issuePermit(frame(), ttlMs = 10, writeBudgetMs = 5)!!
        clock.now = 511
        val result = executor.consume(permit)

        assertEquals(ForwardingExecutionReason.PERMIT_EXPIRED, result.reason)
        assertTrue(sink.frames.isEmpty())
    }

    @Test
    fun cancelledPermitNeverReachesSink() {
        installRuntime()
        val sink = RecordingPermitSink()
        val executor = executor(sink, MutableClock(500))

        val permit = executor.issuePermit(frame(), ttlMs = 100, writeBudgetMs = 10)!!
        assertTrue(permit.cancel())
        val result = executor.consume(permit)

        assertEquals(ForwardingExecutionReason.PERMIT_CANCELLED, result.reason)
        assertTrue(sink.frames.isEmpty())
    }

    @Test
    fun contextRevisionDriftInvalidatesPermit() {
        installRuntime()
        val sink = RecordingPermitSink()
        val session = ForwardingExecutionSession(policy, endpoint, endpoint, destinations)
        val executor = PermitForwardingExecutor(session, sink, MutableClock(500))

        val permit = executor.issuePermit(frame(), ttlMs = 100, writeBudgetMs = 10)!!
        session.updateDestinationPolicy(DestinationPolicy(emptyList()))
        val result = executor.consume(permit)

        assertEquals(ForwardingExecutionReason.PERMIT_REVISION_MISMATCH, result.reason)
        assertTrue(sink.frames.isEmpty())
    }

    @Test
    fun runtimeRevisionDriftInvalidatesPermit() {
        installRuntime()
        val sink = RecordingPermitSink()
        val executor = executor(sink, MutableClock(500))

        val permit = executor.issuePermit(frame(), ttlMs = 100, writeBudgetMs = 10)!!
        SafetyProtocolVpnRuntime.clearProtectedSession()
        val result = executor.consume(permit)

        assertEquals(ForwardingExecutionReason.PERMIT_REVISION_MISMATCH, result.reason)
        assertTrue(sink.frames.isEmpty())
    }

    @Test
    fun permitOwnsImmutableFrameSnapshot() {
        installRuntime()
        val clock = MutableClock(500)
        val sink = RecordingPermitSink()
        val executor = executor(sink, clock)
        val source = frame()
        val expected = source.payload.copyOf()

        val permit = executor.issuePermit(source, ttlMs = 100, writeBudgetMs = 10)!!
        source.payload.fill(0)
        val result = executor.consume(permit)

        assertEquals(ForwardingExecutionDisposition.EXECUTED, result.disposition)
        assertTrue(expected.contentEquals(sink.frames.single().payload))
    }

    @Test
    fun cooperativeWritePastDeadlineFailsClosedAndPoisonsExecutor() {
        installRuntime()
        val clock = MutableClock(500)
        val sink = AdvancingPermitSink(clock, advanceMs = 11)
        val executor = executor(sink, clock)

        val permit = executor.issuePermit(frame(), ttlMs = 100, writeBudgetMs = 10)!!
        val result = executor.consume(permit)

        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, result.disposition)
        assertEquals(ForwardingExecutionReason.WRITE_DEADLINE_EXCEEDED, result.reason)

        val next = executor.issuePermit(frame(sequence = 11), ttlMs = 100, writeBudgetMs = 10)
        assertNull(next)
    }

    @Test
    fun writeExceptionProducesFailureReceiptAndPoisonsExecutor() {
        installRuntime()
        val executor = executor(FailingPermitSink(), MutableClock(500))
        val permit = executor.issuePermit(frame(), ttlMs = 100, writeBudgetMs = 10)!!

        val result = executor.consume(permit)

        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, result.disposition)
        assertEquals(ForwardingExecutionReason.WRITE_FAILED, result.reason)
        assertNotNull(result.receipt)
        assertEquals(ForwardingReceiptDisposition.FAILED_CLOSED, result.receipt!!.disposition)
    }


    @Test
    fun exactExpiryBoundaryIsRejected() {
        installRuntime()
        val clock = MutableClock(500)
        val sink = RecordingPermitSink()
        val executor = executor(sink, clock)

        val permit = executor.issuePermit(frame(), ttlMs = 10, writeBudgetMs = 5)!!
        clock.now = 510
        val result = executor.consume(permit)

        assertEquals(ForwardingExecutionReason.PERMIT_EXPIRED, result.reason)
        assertTrue(sink.frames.isEmpty())
    }

    @Test
    fun clockRegressionFailsClosed() {
        installRuntime()
        val clock = MutableClock(500)
        val sink = RecordingPermitSink()
        val executor = executor(sink, clock)

        val permit = executor.issuePermit(frame(), ttlMs = 100, writeBudgetMs = 10)!!
        clock.now = 499
        val result = executor.consume(permit)

        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, result.disposition)
        assertEquals(ForwardingExecutionReason.CLOCK_REGRESSION, result.reason)
        assertTrue(sink.frames.isEmpty())
        clock.now = 501
        assertEquals(ForwardingExecutionReason.PERMIT_ALREADY_CONSUMED, executor.consume(permit).reason)
    }

    @Test(expected = IllegalArgumentException::class)
    fun ttlAboveHardMaximumIsRejected() {
        installRuntime()
        val executor = executor(RecordingPermitSink(), MutableClock(500))
        executor.issuePermit(frame(), PermitForwardingExecutor.MAX_PERMIT_TTL_MS + 1, 10)
    }

    @Test(expected = IllegalArgumentException::class)
    fun writeBudgetAboveHardMaximumIsRejected() {
        installRuntime()
        val executor = executor(RecordingPermitSink(), MutableClock(500))
        executor.issuePermit(frame(), 500, PermitForwardingExecutor.MAX_WRITE_BUDGET_MS + 1)
    }


    @Test
    fun permitCannotBeConsumedByDifferentExecutor() {
        installRuntime()
        val clock = MutableClock(500)
        val firstSink = RecordingPermitSink()
        val first = executor(firstSink, clock)
        val secondSink = RecordingPermitSink()
        val second = executor(secondSink, clock)

        val permit = first.issuePermit(frame(), ttlMs = 100, writeBudgetMs = 10)!!
        val wrong = second.consume(permit)

        assertEquals(ForwardingExecutionReason.PERMIT_WRONG_OWNER, wrong.reason)
        assertTrue(secondSink.frames.isEmpty())

        val right = first.consume(permit)
        assertEquals(ForwardingExecutionDisposition.EXECUTED, right.disposition)
        assertEquals(1, firstSink.frames.size)
    }

    @Test
    fun livenessExpiryInvalidatesPermitWithoutRuntimeRevisionChange() {
        SafetyProtocolVpnRuntime.update {
            it.copy(
                serviceRunning = true,
                captureEstablished = true,
                osVpnTransportObserved = true,
                transportReadiness = TransportSessionReadiness(
                    authenticatedEstablishment = true,
                    freshLiveness = true,
                    protectedSessionReady = true,
                    validUntilMs = 550,
                    forwardingAuthorized = false,
                ),
            )
        }
        val runtimeRevision = SafetyProtocolVpnRuntime.revision()
        val clock = MutableClock(500)
        val sink = RecordingPermitSink()
        val executor = executor(sink, clock)

        val permit = executor.issuePermit(frame(), ttlMs = 100, writeBudgetMs = 10)!!
        clock.now = 550
        val result = executor.consume(permit)

        assertEquals(runtimeRevision, SafetyProtocolVpnRuntime.revision())
        assertEquals(ForwardingExecutionReason.GATE_NOT_ELIGIBLE, result.reason)
        assertEquals(ForwardingGateReason.PROTECTED_SESSION_NOT_READY, result.gateReason)
        assertTrue(sink.frames.isEmpty())
    }

    private fun executor(
        sink: ForwardingPermitSink,
        clock: MutableClock,
    ): PermitForwardingExecutor {
        val session = ForwardingExecutionSession(policy, endpoint, endpoint, destinations)
        return PermitForwardingExecutor(session, sink, clock)
    }

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
                    validUntilMs = 5_000,
                    forwardingAuthorized = false,
                ),
            )
        }
    }

    private fun frame(sequence: Long = 10): TransportFrame =
        TransportFrame(TransportFrameType.DATA, sequence, publicIpv4TcpPacket())

    private class MutableClock(var now: Long) : ForwardingMonotonicClock {
        override fun nowMs(): Long = now
    }

    private class RecordingPermitSink : ForwardingPermitSink {
        val frames = mutableListOf<TransportFrame>()
        override fun write(frame: TransportFrame, permit: ForwardingExecutionPermit) {
            frames += frame
        }
    }

    private class AdvancingPermitSink(
        private val clock: MutableClock,
        private val advanceMs: Long,
    ) : ForwardingPermitSink {
        override fun write(frame: TransportFrame, permit: ForwardingExecutionPermit) {
            clock.now += advanceMs
        }
    }

    private class FailingPermitSink : ForwardingPermitSink {
        override fun write(frame: TransportFrame, permit: ForwardingExecutionPermit) {
            throw IllegalStateException("simulated partial/unknown write")
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
