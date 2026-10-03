package dev.altru.safetyprotocol.android

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ForwardingExecutorTest {
    private val endpoint = ProtectedTransportEndpoint.fromHexPin(
        host = "relay.example",
        port = 443,
        sha256Hex = "11".repeat(32),
    )

    private val destinationPolicy = DestinationPolicy(
        listOf(DestinationRule.allow("8.8.8.0/24")),
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

    @After
    fun resetRuntime() {
        SafetyProtocolVpnRuntime.reset()
    }

    @Test
    fun eligibleExactFrameWritesOnce() {
        installRuntime(validUntilMs = 1_000)
        val sink = RecordingSink()
        val executor = executor(sink, nowMs = 500)

        val result = execute(executor, frame())

        assertEquals(ForwardingExecutionDisposition.EXECUTED, result.disposition)
        assertEquals(1, sink.frames.size)
        assertEquals(10L, sink.frames.single().sequence)
    }

    @Test
    fun deniedPolicyNeverReachesWriter() {
        installRuntime()
        val sink = RecordingSink()
        val executor = executor(sink)
        val denied = policy.copy(authority = CoreConnectivityAuthority.DENIED)

        val result = executor.execute(
            frame(),
            denied,
            endpoint,
            endpoint,
            destinationPolicy,
        )

        assertEquals(ForwardingExecutionDisposition.DROPPED, result.disposition)
        assertEquals(ForwardingGateReason.POLICY_NOT_AUTHORIZED, result.gateReason)
        assertTrue(sink.frames.isEmpty())
    }

    @Test
    fun livenessExpiryAtExecutionDrops() {
        installRuntime(validUntilMs = 500)
        val sink = RecordingSink()
        val executor = executor(sink, nowMs = 500)

        val result = execute(executor, frame())

        assertEquals(ForwardingExecutionReason.GATE_NOT_ELIGIBLE, result.reason)
        assertEquals(ForwardingGateReason.PROTECTED_SESSION_NOT_READY, result.gateReason)
        assertTrue(sink.frames.isEmpty())
    }

    @Test
    fun captureLossAtExecutionDrops() {
        installRuntime()
        SafetyProtocolVpnRuntime.update { it.copy(captureEstablished = false, transportReadiness = null) }
        val sink = RecordingSink()

        val result = execute(executor(sink), frame())

        assertEquals(ForwardingGateReason.CAPTURE_NOT_ESTABLISHED, result.gateReason)
        assertTrue(sink.frames.isEmpty())
    }

    @Test
    fun relayDriftAtExecutionDrops() {
        installRuntime()
        val sink = RecordingSink()
        val drifted = ProtectedTransportEndpoint.fromHexPin(
            host = "other.example",
            port = 443,
            sha256Hex = "11".repeat(32),
        )

        val result = executor(sink).execute(
            frame(),
            policy,
            endpoint,
            drifted,
            destinationPolicy,
        )

        assertEquals(ForwardingExecutionDisposition.DROPPED, result.disposition)
        assertEquals(ForwardingGateReason.ENDPOINT_BINDING_MISMATCH, result.gateReason)
        assertTrue(sink.frames.isEmpty())
    }

    @Test
    fun destinationPolicyChangeAtExecutionDrops() {
        installRuntime()
        val sink = RecordingSink()

        val result = executor(sink).execute(
            frame(),
            policy,
            endpoint,
            endpoint,
            DestinationPolicy(emptyList()),
        )

        assertEquals(ForwardingExecutionDisposition.DROPPED, result.disposition)
        assertEquals(ForwardingGateReason.DESTINATION_POLICY_NOT_AUTHORIZED, result.gateReason)
        assertTrue(sink.frames.isEmpty())
    }

    @Test
    fun writerFailureFailsClosedWithoutRetry() {
        installRuntime()
        val sink = FailingSink()

        val result = execute(executor(sink), frame())

        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, result.disposition)
        assertEquals(ForwardingExecutionReason.WRITE_FAILED, result.reason)
        assertEquals(1, sink.calls)
    }

    @Test
    fun sameSequenceCannotExecuteTwice() {
        installRuntime()
        val sink = RecordingSink()
        val executor = executor(sink)

        assertEquals(ForwardingExecutionDisposition.EXECUTED, execute(executor, frame(10)).disposition)
        val replay = execute(executor, frame(10))

        assertEquals(ForwardingExecutionDisposition.DROPPED, replay.disposition)
        assertEquals(ForwardingExecutionReason.REPLAY_OR_OUT_OF_ORDER, replay.reason)
        assertEquals(1, sink.frames.size)
    }

    @Test
    fun olderSequenceCannotExecuteAfterNewerOne() {
        installRuntime()
        val sink = RecordingSink()
        val executor = executor(sink)

        assertEquals(ForwardingExecutionDisposition.EXECUTED, execute(executor, frame(11)).disposition)
        val old = execute(executor, frame(10))

        assertEquals(ForwardingExecutionReason.REPLAY_OR_OUT_OF_ORDER, old.reason)
        assertEquals(1, sink.frames.size)
    }

    @Test
    fun failedWritePoisonsExecutorAndPreventsRetry() {
        installRuntime()
        val sink = FailOnceSink()
        val executor = executor(sink)

        val first = execute(executor, frame(10))
        val retry = execute(executor, frame(10))
        val later = execute(executor, frame(11))

        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, first.disposition)
        assertEquals(ForwardingExecutionReason.WRITE_FAILED, first.reason)
        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, retry.disposition)
        assertEquals(ForwardingExecutionReason.EXECUTOR_POISONED, retry.reason)
        assertEquals(ForwardingExecutionReason.EXECUTOR_POISONED, later.reason)
        assertEquals(1, sink.calls)
        assertEquals(0, sink.successfulWrites)
    }

    @Test
    fun clockFailureFailsClosedWithoutWrite() {
        installRuntime()
        val sink = RecordingSink()
        val executor = ForwardingExecutor(
            sink = sink,
            clock = ForwardingMonotonicClock { throw IllegalStateException("clock unavailable") },
        )

        val result = execute(executor, frame())

        assertEquals(ForwardingExecutionDisposition.FAILED_CLOSED, result.disposition)
        assertEquals(ForwardingExecutionReason.EVALUATION_FAILED, result.reason)
        assertTrue(sink.frames.isEmpty())
    }

    @Test
    fun executorSnapshotsPayloadBeforeGateAndWrite() {
        installRuntime()
        val sink = RecordingSink()
        val source = frame()
        val originalFirst = source.payload[0]
        val clock = object : ForwardingMonotonicClock {
            override fun nowMs(): Long {
                source.payload[0] = 0
                return 500
            }
        }
        val executor = ForwardingExecutor(sink, clock)

        val result = execute(executor, source)

        assertEquals(ForwardingExecutionDisposition.EXECUTED, result.disposition)
        assertEquals(originalFirst, sink.frames.single().payload[0])
    }

    private fun installRuntime(validUntilMs: Long = 1_000) {
        SafetyProtocolVpnRuntime.update {
            it.copy(
                serviceRunning = true,
                captureEstablished = true,
                osVpnTransportObserved = true,
                transportReadiness = TransportSessionReadiness(
                    authenticatedEstablishment = true,
                    freshLiveness = true,
                    protectedSessionReady = true,
                    validUntilMs = validUntilMs,
                    forwardingAuthorized = false,
                ),
            )
        }
    }

    private fun executor(
        sink: ForwardingFrameSink,
        nowMs: Long = 500,
    ) = ForwardingExecutor(sink, ForwardingMonotonicClock { nowMs })

    private fun execute(
        executor: ForwardingExecutor,
        frame: TransportFrame,
    ) = executor.execute(
        frame = frame,
        policy = policy,
        authenticatedEndpoint = endpoint,
        candidateEndpoint = endpoint,
        destinationPolicy = destinationPolicy,
    )

    private fun frame(sequence: Long = 10, destinationPort: Int = 443): TransportFrame =
        TransportFrame(
            TransportFrameType.DATA,
            sequence,
            publicIpv4TcpPacket(destinationPort),
        )

    private class RecordingSink : ForwardingFrameSink {
        val frames = mutableListOf<TransportFrame>()
        override fun write(frame: TransportFrame) {
            frames += frame
        }
    }

    private class FailingSink : ForwardingFrameSink {
        var calls = 0
        override fun write(frame: TransportFrame) {
            calls += 1
            throw IllegalStateException("simulated write failure")
        }
    }

    private class FailOnceSink : ForwardingFrameSink {
        var calls = 0
        var successfulWrites = 0

        override fun write(frame: TransportFrame) {
            calls += 1
            if (calls == 1) {
                throw IllegalStateException("simulated first-write failure")
            }
            successfulWrites += 1
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
