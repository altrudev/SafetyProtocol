package dev.altru.safetyprotocol.android

import java.security.MessageDigest
import java.security.SecureRandom

data class TransportLivenessSnapshot(
    val fresh: Boolean,
    val lastAcknowledgedAtMs: Long?,
    val freshUntilMs: Long?,
    val pendingSequence: Long?,
)

class TransportLivenessTracker(
    private val timeoutMs: Long,
    private val freshnessMs: Long,
) {
    init {
        require(timeoutMs > 0)
        require(freshnessMs > 0)
    }

    private data class Pending(
        val sequence: Long,
        val nonce: ByteArray,
        val deadlineMs: Long,
    )

    private val secureRandom = SecureRandom()
    private var nextSequence = 1L
    private var pending: Pending? = null
    private var lastAcknowledgedAtMs: Long? = null

    fun issuePing(nowMs: Long): TransportFrame {
        val nonce = ByteArray(NONCE_BYTES)
        secureRandom.nextBytes(nonce)
        return issuePing(nowMs, nonce)
    }

    @Synchronized
    internal fun issuePing(nowMs: Long, nonce: ByteArray): TransportFrame {
        require(nowMs >= 0)
        require(nonce.size == NONCE_BYTES) { "Liveness nonce must be $NONCE_BYTES bytes" }

        val current = pending
        check(current == null || nowMs > current.deadlineMs) {
            "A liveness challenge is already pending"
        }

        val sequence = nextSequence
        nextSequence = Math.addExact(nextSequence, 1L)
        pending = Pending(
            sequence = sequence,
            nonce = nonce.copyOf(),
            deadlineMs = Math.addExact(nowMs, timeoutMs),
        )
        return TransportFrame(TransportFrameType.PING, sequence, nonce.copyOf())
    }

    @Synchronized
    fun acceptPong(frame: TransportFrame, nowMs: Long): Boolean {
        require(nowMs >= 0)
        val expected = pending ?: return false
        if (frame.type != TransportFrameType.PONG) return false
        if (frame.sequence != expected.sequence) return false
        if (nowMs > expected.deadlineMs) {
            pending = null
            return false
        }
        if (!MessageDigest.isEqual(expected.nonce, frame.payload)) return false

        pending = null
        lastAcknowledgedAtMs = nowMs
        return true
    }

    @Synchronized
    fun snapshot(nowMs: Long): TransportLivenessSnapshot {
        require(nowMs >= 0)
        val currentPending = pending
        val pendingExpired = currentPending != null && nowMs > currentPending.deadlineMs
        if (pendingExpired) pending = null

        val acknowledgedAt = lastAcknowledgedAtMs
        val freshUntilMs = acknowledgedAt?.let { Math.addExact(it, freshnessMs) }
        val withinFreshness = acknowledgedAt != null &&
            freshUntilMs != null &&
            nowMs >= acknowledgedAt &&
            nowMs < freshUntilMs
        return TransportLivenessSnapshot(
            fresh = withinFreshness && !pendingExpired,
            lastAcknowledgedAtMs = acknowledgedAt,
            freshUntilMs = freshUntilMs,
            pendingSequence = pending?.sequence,
        )
    }

    companion object {
        const val NONCE_BYTES = 16

        fun pongFor(ping: TransportFrame): TransportFrame {
            require(ping.type == TransportFrameType.PING)
            require(ping.payload.size == NONCE_BYTES)
            return TransportFrame(TransportFrameType.PONG, ping.sequence, ping.payload.copyOf())
        }
    }
}
