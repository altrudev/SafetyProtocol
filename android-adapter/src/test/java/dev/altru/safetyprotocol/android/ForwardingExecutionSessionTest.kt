package dev.altru.safetyprotocol.android

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ForwardingExecutionSessionTest {
    private val endpoint = ProtectedTransportEndpoint.fromHexPin(
        host = "relay.example",
        port = 443,
        sha256Hex = "11".repeat(32),
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

    private val allowPublic = DestinationPolicy(
        listOf(DestinationRule.allow("8.8.8.0/24")),
    )

    @After
    fun resetRuntime() {
        SafetyProtocolVpnRuntime.reset()
    }

    @Test
    fun contextRevisionAdvancesOnEveryCommittedContextChange() {
        val session = session()
        val initial = session.revision()

        session.updateDestinationPolicy(DestinationPolicy(emptyList()))
        assertEquals(initial + 1, session.revision())

        session.updateCandidateEndpoint(
            ProtectedTransportEndpoint.fromHexPin("other.example", 443, "11".repeat(32)),
        )
        assertEquals(initial + 2, session.revision())
    }

    @Test
    fun runtimeRevisionAdvancesOnEveryCommittedRuntimeChange() {
        val initial = SafetyProtocolVpnRuntime.revision()
        SafetyProtocolVpnRuntime.update { it.copy(serviceRunning = true) }
        assertEquals(initial + 1, SafetyProtocolVpnRuntime.revision())
        SafetyProtocolVpnRuntime.clearProtectedSession()
        assertEquals(initial + 2, SafetyProtocolVpnRuntime.revision())
    }

    @Test
    fun successfulWriteCarriesCompositeExecutionRevision() {
        installRuntime()
        val sink = RecordingRevisionSink()
        val session = session()
        val executor = ForwardingExecutor(
            session = session,
            sink = sink,
            clock = ForwardingMonotonicClock { 500 },
        )

        val result = executor.execute(frame())

        assertEquals(ForwardingExecutionDisposition.EXECUTED, result.disposition)
        assertNotNull(result.executionRevision)
        assertEquals(result.executionRevision, sink.writes.single().revision)
        assertEquals(session.revision(), result.executionRevision!!.contextRevision)
        assertEquals(SafetyProtocolVpnRuntime.revision(), result.executionRevision!!.runtimeRevision)
    }

    @Test
    fun contextUpdateCannotCommitDuringWriterCriticalSection() {
        installRuntime()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val updateFinished = CountDownLatch(1)
        val sink = BlockingRevisionSink(entered, release)
        val session = session()
        val executor = ForwardingExecutor(
            session = session,
            sink = sink,
            clock = ForwardingMonotonicClock { 500 },
        )

        val execution = thread(start = true) {
            executor.execute(frame())
        }

        assertTrue(entered.await(2, TimeUnit.SECONDS))
        val update = thread(start = true) {
            session.updateDestinationPolicy(DestinationPolicy(emptyList()))
            updateFinished.countDown()
        }

        assertFalse(updateFinished.await(150, TimeUnit.MILLISECONDS))
        release.countDown()
        execution.join(2_000)
        update.join(2_000)
        assertTrue(updateFinished.await(1, TimeUnit.SECONDS))

        val second = executor.execute(frame(sequence = 11))
        assertEquals(ForwardingExecutionDisposition.DROPPED, second.disposition)
        assertEquals(ForwardingGateReason.DESTINATION_POLICY_NOT_AUTHORIZED, second.gateReason)
    }

    @Test
    fun runtimeUpdateCannotCommitDuringWriterCriticalSection() {
        installRuntime()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val updateFinished = CountDownLatch(1)
        val sink = BlockingRevisionSink(entered, release)
        val session = session()
        val executor = ForwardingExecutor(
            session = session,
            sink = sink,
            clock = ForwardingMonotonicClock { 500 },
        )

        val execution = thread(start = true) {
            executor.execute(frame())
        }

        assertTrue(entered.await(2, TimeUnit.SECONDS))
        val update = thread(start = true) {
            SafetyProtocolVpnRuntime.clearProtectedSession()
            updateFinished.countDown()
        }

        assertFalse(updateFinished.await(150, TimeUnit.MILLISECONDS))
        release.countDown()
        execution.join(2_000)
        update.join(2_000)
        assertTrue(updateFinished.await(1, TimeUnit.SECONDS))

        val second = executor.execute(frame(sequence = 11))
        assertEquals(ForwardingExecutionDisposition.DROPPED, second.disposition)
        assertEquals(ForwardingGateReason.PROTECTED_SESSION_NOT_READY, second.gateReason)
    }

    @Test
    fun endpointPinInputIsDefensivelyCopiedBySession() {
        val pin = ByteArray(32) { 0x11 }
        val mutableEndpoint = ProtectedTransportEndpoint("relay.example", 443, pin)
        val session = ForwardingExecutionSession(
            policy = policy,
            authenticatedEndpoint = mutableEndpoint,
            candidateEndpoint = mutableEndpoint,
            destinationPolicy = allowPublic,
        )

        pin[0] = 0x22
        mutableEndpoint.spkiSha256[1] = 0x22

        installRuntime()
        val sink = RecordingRevisionSink()
        val result = ForwardingExecutor(
            session,
            sink,
            ForwardingMonotonicClock { 500 },
        ).execute(frame())

        assertEquals(ForwardingExecutionDisposition.EXECUTED, result.disposition)
    }


    @Test
    fun reentrantContextMutationFromWriterFailsClosedAndDoesNotAdvanceRevision() {
        installRuntime()
        val session = session()
        val before = session.revision()
        val sink = object : ForwardingFrameSink {
            override fun write(frame: TransportFrame, revision: ForwardingExecutionRevision) {
                session.updateDestinationPolicy(DestinationPolicy(emptyList()))
            }
        }
        val executor = ForwardingExecutor(
            session,
            sink,
            ForwardingMonotonicClock { 500 },
        )

        val result = executor.execute(frame())

        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, result.disposition)
        assertEquals(ForwardingExecutionReason.WRITE_FAILED, result.reason)
        assertEquals(before, session.revision())
    }

    @Test
    fun reentrantRuntimeMutationFromWriterFailsClosedAndDoesNotAdvanceRevision() {
        installRuntime()
        val session = session()
        val before = SafetyProtocolVpnRuntime.revision()
        val sink = object : ForwardingFrameSink {
            override fun write(frame: TransportFrame, revision: ForwardingExecutionRevision) {
                SafetyProtocolVpnRuntime.clearProtectedSession()
            }
        }
        val executor = ForwardingExecutor(
            session,
            sink,
            ForwardingMonotonicClock { 500 },
        )

        val result = executor.execute(frame())

        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, result.disposition)
        assertEquals(ForwardingExecutionReason.WRITE_FAILED, result.reason)
        assertEquals(before, SafetyProtocolVpnRuntime.revision())
    }


    @Test
    fun deniedExecutionStillCarriesCompositeRevisionEvidence() {
        installRuntime()
        val session = session()
        session.updateDestinationPolicy(DestinationPolicy(emptyList()))
        val sink = RecordingRevisionSink()
        val executor = ForwardingExecutor(
            session,
            sink,
            ForwardingMonotonicClock { 500 },
        )

        val result = executor.execute(frame())

        assertEquals(ForwardingExecutionDisposition.DROPPED, result.disposition)
        assertNotNull(result.executionRevision)
        assertEquals(session.revision(), result.executionRevision!!.contextRevision)
        assertEquals(SafetyProtocolVpnRuntime.revision(), result.executionRevision!!.runtimeRevision)
        assertTrue(sink.writes.isEmpty())
    }

    private fun session() = ForwardingExecutionSession(
        policy = policy,
        authenticatedEndpoint = endpoint,
        candidateEndpoint = endpoint,
        destinationPolicy = allowPublic,
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
                    validUntilMs = 1_000,
                    forwardingAuthorized = false,
                ),
            )
        }
    }

    private fun frame(sequence: Long = 10): TransportFrame =
        TransportFrame(TransportFrameType.DATA, sequence, publicIpv4TcpPacket(443))

    private class RecordingRevisionSink : ForwardingFrameSink {
        data class Write(val frame: TransportFrame, val revision: ForwardingExecutionRevision)
        val writes = mutableListOf<Write>()

        override fun write(frame: TransportFrame, revision: ForwardingExecutionRevision) {
            writes += Write(frame, revision)
        }
    }

    private class BlockingRevisionSink(
        private val entered: CountDownLatch,
        private val release: CountDownLatch,
    ) : ForwardingFrameSink {
        override fun write(frame: TransportFrame, revision: ForwardingExecutionRevision) {
            entered.countDown()
            check(release.await(2, TimeUnit.SECONDS))
        }
    }

    private fun publicIpv4TcpPacket(destinationPort: Int): ByteArray {
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
        packet[22] = (destinationPort ushr 8).toByte()
        packet[23] = destinationPort.toByte()
        packet[32] = 0x50
        return packet
    }
}
