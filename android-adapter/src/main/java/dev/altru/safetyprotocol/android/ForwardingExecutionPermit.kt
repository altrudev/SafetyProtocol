package dev.altru.safetyprotocol.android

internal enum class ForwardingReceiptDisposition {
    EXECUTED,
    DROPPED,
    FAILED_CLOSED,
}

internal data class ForwardingExecutionReceipt(
    val permitId: Long,
    val revision: ForwardingExecutionRevision,
    val frameSequence: Long,
    val frameLength: Int,
    val disposition: ForwardingReceiptDisposition,
    val reason: ForwardingExecutionReason,
    val issuedAtMs: Long,
    val terminalAtMs: Long,
)

internal fun interface ForwardingPermitSink {
    fun write(
        frame: TransportFrame,
        permit: ForwardingExecutionPermit,
    )
}

internal enum class PermitClaimResult {
    CLAIMED,
    CANCELLED,
    EXPIRED,
    ALREADY_CONSUMED,
    WRONG_OWNER,
    CLOCK_REGRESSION,
}

internal class ForwardingExecutionPermit internal constructor(
    val permitId: Long,
    val revision: ForwardingExecutionRevision,
    val issuedAtMs: Long,
    val expiresAtMs: Long,
    val writeBudgetMs: Long,
    private val ownerToken: Any,
    frame: TransportFrame,
) {
    private enum class State {
        ISSUED,
        CANCELLED,
        CONSUMED,
    }

    private var state = State.ISSUED
    private val frameSnapshot = TransportFrame(
        type = frame.type,
        sequence = frame.sequence,
        payload = frame.payload.copyOf(),
    )

    val frameSequence: Long
        get() = frameSnapshot.sequence

    val frameLength: Int
        get() = frameSnapshot.payload.size

    @Synchronized
    fun cancel(): Boolean {
        if (state != State.ISSUED) return false
        state = State.CANCELLED
        return true
    }

    @Synchronized
    internal fun claim(
        callerToken: Any,
        nowMs: Long,
    ): PermitClaimResult {
        if (callerToken !== ownerToken) return PermitClaimResult.WRONG_OWNER
        return when (state) {
            State.CANCELLED -> PermitClaimResult.CANCELLED
            State.CONSUMED -> PermitClaimResult.ALREADY_CONSUMED
            State.ISSUED -> {
                if (nowMs < issuedAtMs) {
                    state = State.CONSUMED
                    PermitClaimResult.CLOCK_REGRESSION
                } else if (nowMs >= expiresAtMs) {
                    state = State.CONSUMED
                    PermitClaimResult.EXPIRED
                } else {
                    state = State.CONSUMED
                    PermitClaimResult.CLAIMED
                }
            }
        }
    }


    @Synchronized
    internal fun invalidate(callerToken: Any): Boolean {
        if (callerToken !== ownerToken || state != State.ISSUED) return false
        state = State.CONSUMED
        return true
    }

    internal fun frameCopy() = TransportFrame(
        type = frameSnapshot.type,
        sequence = frameSnapshot.sequence,
        payload = frameSnapshot.payload.copyOf(),
    )
}

internal class PermitForwardingExecutor(
    val session: ForwardingExecutionSession,
    private val sink: ForwardingPermitSink,
    private val clock: ForwardingMonotonicClock = ForwardingMonotonicClock {
        System.nanoTime() / 1_000_000L
    },
) {
    companion object {
        const val MAX_PERMIT_TTL_MS = 1_000L
        const val MAX_WRITE_BUDGET_MS = 250L
    }

    private val ownerToken = Any()
    private var nextPermitId = 1L
    private var lastExecutedSequence: Long? = null
    private var poisoned = false

    @Synchronized
    fun issuePermit(
        frame: TransportFrame,
        ttlMs: Long,
        writeBudgetMs: Long,
    ): ForwardingExecutionPermit? {
        if (poisoned) return null
        require(ttlMs in 1..MAX_PERMIT_TTL_MS)
        require(writeBudgetMs in 1..MAX_WRITE_BUDGET_MS)
        require(writeBudgetMs <= ttlMs)

        val exactFrame = TransportFrame(
            type = frame.type,
            sequence = frame.sequence,
            payload = frame.payload.copyOf(),
        )

        return session.withStableContext { context ->
            SafetyProtocolVpnRuntime.withStableSnapshot { runtime, runtimeRevision ->
                val now = try {
                    clock.nowMs()
                } catch (_: Throwable) {
                    return@withStableSnapshot null
                }
                val gate = try {
                    ForwardingGate.evaluate(
                        runtime = runtime,
                        policy = context.policy,
                        authenticatedEndpoint = context.authenticatedEndpoint,
                        candidateEndpoint = context.candidateEndpoint,
                        destinationPolicy = context.destinationPolicy,
                        frame = exactFrame,
                        nowMs = now,
                    )
                } catch (_: Throwable) {
                    return@withStableSnapshot null
                }
                if (!gate.eligible) return@withStableSnapshot null

                val last = lastExecutedSequence
                if (last != null && exactFrame.sequence <= last) {
                    return@withStableSnapshot null
                }

                val expires = try {
                    Math.addExact(now, ttlMs)
                } catch (_: ArithmeticException) {
                    return@withStableSnapshot null
                }
                val id = try {
                    nextPermitId.also { nextPermitId = Math.addExact(it, 1L) }
                } catch (_: ArithmeticException) {
                    return@withStableSnapshot null
                }

                ForwardingExecutionPermit(
                    permitId = id,
                    revision = ForwardingExecutionRevision(context.revision, runtimeRevision),
                    issuedAtMs = now,
                    expiresAtMs = expires,
                    writeBudgetMs = writeBudgetMs,
                    ownerToken = ownerToken,
                    frame = exactFrame,
                )
            }
        }
    }

    @Synchronized
    fun consume(permit: ForwardingExecutionPermit): ForwardingExecutionResult {
        if (poisoned) {
            return ForwardingExecutionResult(
                disposition = ForwardingExecutionDisposition.FAILED_CLOSED,
                reason = ForwardingExecutionReason.EXECUTOR_POISONED,
            )
        }

        val claimTime = try {
            clock.nowMs()
        } catch (_: Throwable) {
            permit.invalidate(ownerToken)
            return terminal(
                permit,
                ForwardingExecutionDisposition.FAILED_CLOSED,
                ForwardingExecutionReason.EVALUATION_FAILED,
                permit.issuedAtMs,
            )
        }

        when (permit.claim(ownerToken, claimTime)) {
            PermitClaimResult.CANCELLED ->
                return terminal(permit, ForwardingExecutionDisposition.DROPPED, ForwardingExecutionReason.PERMIT_CANCELLED, claimTime)
            PermitClaimResult.EXPIRED ->
                return terminal(permit, ForwardingExecutionDisposition.DROPPED, ForwardingExecutionReason.PERMIT_EXPIRED, claimTime)
            PermitClaimResult.ALREADY_CONSUMED ->
                return terminal(permit, ForwardingExecutionDisposition.DROPPED, ForwardingExecutionReason.PERMIT_ALREADY_CONSUMED, claimTime)
            PermitClaimResult.WRONG_OWNER ->
                return terminal(permit, ForwardingExecutionDisposition.DROPPED, ForwardingExecutionReason.PERMIT_WRONG_OWNER, claimTime)
            PermitClaimResult.CLOCK_REGRESSION ->
                return terminal(permit, ForwardingExecutionDisposition.FAILED_CLOSED, ForwardingExecutionReason.CLOCK_REGRESSION, claimTime)
            PermitClaimResult.CLAIMED -> Unit
        }

        val exactFrame = permit.frameCopy()

        return session.withStableContext { context ->
            SafetyProtocolVpnRuntime.withStableSnapshot { runtime, runtimeRevision ->
                val currentRevision = ForwardingExecutionRevision(context.revision, runtimeRevision)
                if (currentRevision != permit.revision) {
                    return@withStableSnapshot terminal(
                        permit,
                        ForwardingExecutionDisposition.DROPPED,
                        ForwardingExecutionReason.PERMIT_REVISION_MISMATCH,
                        safeNow(claimTime),
                    )
                }

                val now = safeNow(claimTime)
                if (now < claimTime) {
                    return@withStableSnapshot terminal(
                        permit,
                        ForwardingExecutionDisposition.FAILED_CLOSED,
                        ForwardingExecutionReason.CLOCK_REGRESSION,
                        now,
                    )
                }
                if (now >= permit.expiresAtMs) {
                    return@withStableSnapshot terminal(
                        permit,
                        ForwardingExecutionDisposition.DROPPED,
                        ForwardingExecutionReason.PERMIT_EXPIRED,
                        now,
                    )
                }

                val gate = try {
                    ForwardingGate.evaluate(
                        runtime = runtime,
                        policy = context.policy,
                        authenticatedEndpoint = context.authenticatedEndpoint,
                        candidateEndpoint = context.candidateEndpoint,
                        destinationPolicy = context.destinationPolicy,
                        frame = exactFrame,
                        nowMs = now,
                    )
                } catch (_: Throwable) {
                    return@withStableSnapshot terminal(
                        permit,
                        ForwardingExecutionDisposition.FAILED_CLOSED,
                        ForwardingExecutionReason.EVALUATION_FAILED,
                        safeNow(now),
                    )
                }

                if (!gate.eligible) {
                    return@withStableSnapshot terminal(
                        permit,
                        ForwardingExecutionDisposition.DROPPED,
                        ForwardingExecutionReason.GATE_NOT_ELIGIBLE,
                        safeNow(now),
                        gate.reason,
                    )
                }

                val last = lastExecutedSequence
                if (last != null && exactFrame.sequence <= last) {
                    return@withStableSnapshot terminal(
                        permit,
                        ForwardingExecutionDisposition.DROPPED,
                        ForwardingExecutionReason.REPLAY_OR_OUT_OF_ORDER,
                        safeNow(now),
                        gate.reason,
                    )
                }

                val writeDeadline = try {
                    minOf(permit.expiresAtMs, Math.addExact(now, permit.writeBudgetMs))
                } catch (_: ArithmeticException) {
                    poisoned = true
                    return@withStableSnapshot terminal(
                        permit,
                        ForwardingExecutionDisposition.FAILED_CLOSED,
                        ForwardingExecutionReason.WRITE_DEADLINE_EXCEEDED,
                        safeNow(now),
                        gate.reason,
                    )
                }

                try {
                    sink.write(exactFrame, permit)
                } catch (_: Throwable) {
                    poisoned = true
                    return@withStableSnapshot terminal(
                        permit,
                        ForwardingExecutionDisposition.FAILED_CLOSED,
                        ForwardingExecutionReason.WRITE_FAILED,
                        safeNow(now),
                        gate.reason,
                    )
                }

                val completedAt = safeNow(now)
                if (completedAt < now) {
                    poisoned = true
                    return@withStableSnapshot terminal(
                        permit,
                        ForwardingExecutionDisposition.FAILED_CLOSED,
                        ForwardingExecutionReason.CLOCK_REGRESSION,
                        completedAt,
                        gate.reason,
                    )
                }
                if (completedAt > writeDeadline) {
                    poisoned = true
                    return@withStableSnapshot terminal(
                        permit,
                        ForwardingExecutionDisposition.FAILED_CLOSED,
                        ForwardingExecutionReason.WRITE_DEADLINE_EXCEEDED,
                        completedAt,
                        gate.reason,
                    )
                }

                lastExecutedSequence = exactFrame.sequence
                terminal(
                    permit,
                    ForwardingExecutionDisposition.EXECUTED,
                    ForwardingExecutionReason.EXECUTED,
                    completedAt,
                    gate.reason,
                )
            }
        }
    }

    private fun safeNow(fallback: Long): Long =
        try {
            clock.nowMs()
        } catch (_: Throwable) {
            fallback
        }

    private fun terminal(
        permit: ForwardingExecutionPermit,
        disposition: ForwardingExecutionDisposition,
        reason: ForwardingExecutionReason,
        terminalAtMs: Long,
        gateReason: ForwardingGateReason? = null,
    ): ForwardingExecutionResult {
        val receiptDisposition = when (disposition) {
            ForwardingExecutionDisposition.EXECUTED -> ForwardingReceiptDisposition.EXECUTED
            ForwardingExecutionDisposition.DROPPED -> ForwardingReceiptDisposition.DROPPED
            ForwardingExecutionDisposition.FAILED_CLOSED -> ForwardingReceiptDisposition.FAILED_CLOSED
        }
        return ForwardingExecutionResult(
            disposition = disposition,
            reason = reason,
            gateReason = gateReason,
            executionRevision = permit.revision,
            receipt = ForwardingExecutionReceipt(
                permitId = permit.permitId,
                revision = permit.revision,
                frameSequence = permit.frameSequence,
                frameLength = permit.frameLength,
                disposition = receiptDisposition,
                reason = reason,
                issuedAtMs = permit.issuedAtMs,
                terminalAtMs = terminalAtMs,
            ),
        )
    }
}
