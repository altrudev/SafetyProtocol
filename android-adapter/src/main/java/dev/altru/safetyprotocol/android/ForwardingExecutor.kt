package dev.altru.safetyprotocol.android

internal fun interface ForwardingFrameSink {
    fun write(
        frame: TransportFrame,
        revision: ForwardingExecutionRevision,
    )
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
    PERMIT_CANCELLED,
    PERMIT_EXPIRED,
    PERMIT_ALREADY_CONSUMED,
    PERMIT_REVISION_MISMATCH,
    PERMIT_WRONG_OWNER,
    WRITE_DEADLINE_EXCEEDED,
    CLOCK_REGRESSION,
    WRITE_CANCELLATION_UNCONFIRMED,
}

internal data class ForwardingExecutionResult(
    val disposition: ForwardingExecutionDisposition,
    val reason: ForwardingExecutionReason,
    val gateReason: ForwardingGateReason? = null,
    val executionRevision: ForwardingExecutionRevision? = null,
    val receipt: ForwardingExecutionReceipt? = null,
    val receiptPersistence: ForwardingReceiptPersistence = ForwardingReceiptPersistence.NOT_ATTEMPTED,
)

internal class ForwardingExecutor(
    private val session: ForwardingExecutionSession,
    private val sink: ForwardingFrameSink,
    private val clock: ForwardingMonotonicClock = ForwardingMonotonicClock {
        System.nanoTime() / 1_000_000L
    },
) {
    private var lastExecutedSequence: Long? = null
    private var poisoned = false

    @Synchronized
    fun execute(frame: TransportFrame): ForwardingExecutionResult {
        if (poisoned) {
            return failed(ForwardingExecutionReason.EXECUTOR_POISONED)
        }

        val exactFrame = TransportFrame(
            type = frame.type,
            sequence = frame.sequence,
            payload = frame.payload.copyOf(),
        )

        return session.withStableContext { context ->
            SafetyProtocolVpnRuntime.withStableSnapshot { runtime, runtimeRevision ->
                executeStable(
                    exactFrame = exactFrame,
                    context = context,
                    runtime = runtime,
                    runtimeRevision = runtimeRevision,
                )
            }
        }
    }

    private fun executeStable(
        exactFrame: TransportFrame,
        context: ForwardingExecutionContext,
        runtime: VpnRuntimeSnapshot,
        runtimeRevision: Long,
    ): ForwardingExecutionResult {
        val revision = ForwardingExecutionRevision(
            contextRevision = context.revision,
            runtimeRevision = runtimeRevision,
        )

        val gate = try {
            ForwardingGate.evaluate(
                runtime = runtime,
                policy = context.policy,
                authenticatedEndpoint = context.authenticatedEndpoint,
                candidateEndpoint = context.candidateEndpoint,
                destinationPolicy = context.destinationPolicy,
                frame = exactFrame,
                nowMs = clock.nowMs(),
            )
        } catch (_: Throwable) {
            return failed(
                reason = ForwardingExecutionReason.EVALUATION_FAILED,
                revision = revision,
            )
        }

        if (!gate.eligible) {
            return ForwardingExecutionResult(
                disposition = ForwardingExecutionDisposition.DROPPED,
                reason = ForwardingExecutionReason.GATE_NOT_ELIGIBLE,
                gateReason = gate.reason,
                executionRevision = revision,
            )
        }

        val last = lastExecutedSequence
        if (last != null && exactFrame.sequence <= last) {
            return ForwardingExecutionResult(
                disposition = ForwardingExecutionDisposition.DROPPED,
                reason = ForwardingExecutionReason.REPLAY_OR_OUT_OF_ORDER,
                gateReason = gate.reason,
                executionRevision = revision,
            )
        }

        try {
            sink.write(exactFrame, revision)
        } catch (_: Throwable) {
            poisoned = true
            return failed(
                reason = ForwardingExecutionReason.WRITE_FAILED,
                gateReason = gate.reason,
                revision = revision,
            )
        }

        lastExecutedSequence = exactFrame.sequence
        return ForwardingExecutionResult(
            disposition = ForwardingExecutionDisposition.EXECUTED,
            reason = ForwardingExecutionReason.EXECUTED,
            gateReason = gate.reason,
            executionRevision = revision,
        )
    }

    private fun failed(
        reason: ForwardingExecutionReason,
        gateReason: ForwardingGateReason? = null,
        revision: ForwardingExecutionRevision? = null,
    ) = ForwardingExecutionResult(
        disposition = ForwardingExecutionDisposition.FAILED_CLOSED,
        reason = reason,
        gateReason = gateReason,
        executionRevision = revision,
    )
}
