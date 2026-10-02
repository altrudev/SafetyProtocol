package dev.altru.safetyprotocol.android

internal fun interface ForwardingFrameSink {
    fun write(frame: TransportFrame)
}

internal fun interface ForwardingMonotonicClock {
    fun nowMs(): Long
}

internal enum class ForwardingExecutionDisposition {
    EXECUTED,
    DROPPED,
    FAILED_CLOSED,
}

internal enum class ForwardingExecutionReason {
    EXECUTED,
    GATE_NOT_ELIGIBLE,
    REPLAY_OR_OUT_OF_ORDER,
    EVALUATION_FAILED,
    WRITE_FAILED,
    EXECUTOR_POISONED,
}

internal data class ForwardingExecutionResult(
    val disposition: ForwardingExecutionDisposition,
    val reason: ForwardingExecutionReason,
    val gateReason: ForwardingGateReason? = null,
)

internal class ForwardingExecutor(
    private val sink: ForwardingFrameSink,
    private val clock: ForwardingMonotonicClock = ForwardingMonotonicClock {
        System.nanoTime() / 1_000_000L
    },
) {
    private var lastExecutedSequence: Long? = null
    private var poisoned = false

    @Synchronized
    fun execute(
        frame: TransportFrame,
        policy: CoreConnectivityDecision,
        authenticatedEndpoint: ProtectedTransportEndpoint,
        candidateEndpoint: ProtectedTransportEndpoint,
        destinationPolicy: DestinationPolicy,
    ): ForwardingExecutionResult {
        if (poisoned) {
            return failed(ForwardingExecutionReason.EXECUTOR_POISONED)
        }

        val exactFrame = TransportFrame(
            type = frame.type,
            sequence = frame.sequence,
            payload = frame.payload.copyOf(),
        )

        val gate = try {
            ForwardingGate.evaluate(
                runtime = SafetyProtocolVpnRuntime.snapshot(),
                policy = policy,
                authenticatedEndpoint = authenticatedEndpoint,
                candidateEndpoint = candidateEndpoint,
                destinationPolicy = destinationPolicy,
                frame = exactFrame,
                nowMs = clock.nowMs(),
            )
        } catch (_: Throwable) {
            return failed(ForwardingExecutionReason.EVALUATION_FAILED)
        }

        if (!gate.eligible) {
            return ForwardingExecutionResult(
                disposition = ForwardingExecutionDisposition.DROPPED,
                reason = ForwardingExecutionReason.GATE_NOT_ELIGIBLE,
                gateReason = gate.reason,
            )
        }

        val last = lastExecutedSequence
        if (last != null && exactFrame.sequence <= last) {
            return ForwardingExecutionResult(
                disposition = ForwardingExecutionDisposition.DROPPED,
                reason = ForwardingExecutionReason.REPLAY_OR_OUT_OF_ORDER,
                gateReason = gate.reason,
            )
        }

        try {
            sink.write(exactFrame)
        } catch (_: Throwable) {
            poisoned = true
            return failed(ForwardingExecutionReason.WRITE_FAILED, gate.reason)
        }

        lastExecutedSequence = exactFrame.sequence
        return ForwardingExecutionResult(
            disposition = ForwardingExecutionDisposition.EXECUTED,
            reason = ForwardingExecutionReason.EXECUTED,
            gateReason = gate.reason,
        )
    }

    private fun failed(
        reason: ForwardingExecutionReason,
        gateReason: ForwardingGateReason? = null,
    ) = ForwardingExecutionResult(
        disposition = ForwardingExecutionDisposition.FAILED_CLOSED,
        reason = reason,
        gateReason = gateReason,
    )
}
