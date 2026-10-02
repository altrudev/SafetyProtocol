package dev.altru.safetyprotocol.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportLivenessTrackerTest {
    private val nonce = ByteArray(TransportLivenessTracker.NONCE_BYTES) { it.toByte() }

    @Test
    fun pingAloneDoesNotCreateFreshLiveness() {
        val tracker = TransportLivenessTracker(timeoutMs = 1_000, freshnessMs = 5_000)
        tracker.issuePing(nowMs = 100, nonce = nonce)
        assertFalse(tracker.snapshot(nowMs = 100).fresh)
    }

    @Test
    fun matchingPongCreatesFreshLiveness() {
        val tracker = TransportLivenessTracker(timeoutMs = 1_000, freshnessMs = 5_000)
        val ping = tracker.issuePing(nowMs = 100, nonce = nonce)
        val pong = TransportFrame(TransportFrameType.PONG, ping.sequence, nonce.copyOf())
        assertTrue(tracker.acceptPong(pong, nowMs = 500))
        assertTrue(tracker.snapshot(nowMs = 500).fresh)
    }

    @Test
    fun wrongNonceFailsClosed() {
        val tracker = TransportLivenessTracker(timeoutMs = 1_000, freshnessMs = 5_000)
        val ping = tracker.issuePing(nowMs = 100, nonce = nonce)
        val wrong = nonce.copyOf().also { it[0] = 99 }
        assertFalse(tracker.acceptPong(TransportFrame(TransportFrameType.PONG, ping.sequence, wrong), 200))
        assertFalse(tracker.snapshot(200).fresh)
    }

    @Test
    fun wrongSequenceFailsClosed() {
        val tracker = TransportLivenessTracker(timeoutMs = 1_000, freshnessMs = 5_000)
        tracker.issuePing(nowMs = 100, nonce = nonce)
        assertFalse(tracker.acceptPong(TransportFrame(TransportFrameType.PONG, 999, nonce), 200))
    }

    @Test
    fun latePongFailsClosed() {
        val tracker = TransportLivenessTracker(timeoutMs = 1_000, freshnessMs = 5_000)
        val ping = tracker.issuePing(nowMs = 100, nonce = nonce)
        assertFalse(tracker.acceptPong(TransportFrame(TransportFrameType.PONG, ping.sequence, nonce), 1_101))
        assertFalse(tracker.snapshot(1_101).fresh)
    }

    @Test
    fun replayedPongIsRejected() {
        val tracker = TransportLivenessTracker(timeoutMs = 1_000, freshnessMs = 5_000)
        val ping = tracker.issuePing(nowMs = 100, nonce = nonce)
        val pong = TransportFrame(TransportFrameType.PONG, ping.sequence, nonce)
        assertTrue(tracker.acceptPong(pong, 200))
        assertFalse(tracker.acceptPong(pong, 300))
    }

    @Test
    fun freshnessExpires() {
        val tracker = TransportLivenessTracker(timeoutMs = 1_000, freshnessMs = 5_000)
        val ping = tracker.issuePing(nowMs = 100, nonce = nonce)
        tracker.acceptPong(TransportFrame(TransportFrameType.PONG, ping.sequence, nonce), 200)
        assertTrue(tracker.snapshot(5_199).fresh)
        assertFalse(tracker.snapshot(5_201).fresh)
    }
}
