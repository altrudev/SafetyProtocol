package dev.altru.safetyprotocol.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnEnforcementPolicyTest {
    @Test
    fun noCaptureCannotClaimFailClosed() {
        val state = VpnRuntimeSnapshot()
        val decision = VpnEnforcementPolicy.evaluate(state)

        assertEquals(TrafficDisposition.NOT_ENFORCED, decision.disposition)
        assertFalse(decision.sessionFailClosedVerified)
        assertFalse(decision.persistentFailClosedVerified)
    }

    @Test
    fun establishedCaptureDropsByDefault() {
        val state = VpnRuntimeSnapshot(
            serviceRunning = true,
            captureEstablished = true,
            osVpnTransportObserved = true,
        )
        val decision = VpnEnforcementPolicy.evaluate(state)

        assertEquals(TrafficDisposition.DROP_FAIL_CLOSED, decision.disposition)
        assertTrue(decision.sessionFailClosedVerified)
        assertFalse(decision.persistentFailClosedVerified)
    }

    @Test
    fun osObservationDoesNotCreateCapture() {
        val state = VpnRuntimeSnapshot(
            serviceRunning = true,
            captureEstablished = false,
            osVpnTransportObserved = true,
        )
        val decision = VpnEnforcementPolicy.evaluate(state)

        assertEquals(TrafficDisposition.NOT_ENFORCED, decision.disposition)
        assertFalse(decision.sessionFailClosedVerified)
    }

    @Test
    fun persistentFailClosedRequiresAlwaysOnAndLockdown() {
        val base = VpnRuntimeSnapshot(serviceRunning = true, captureEstablished = true)

        assertFalse(VpnEnforcementPolicy.evaluate(base.copy(alwaysOn = true)).persistentFailClosedVerified)
        assertFalse(VpnEnforcementPolicy.evaluate(base.copy(lockdownEnabled = true)).persistentFailClosedVerified)
        assertTrue(
            VpnEnforcementPolicy.evaluate(base.copy(alwaysOn = true, lockdownEnabled = true))
                .persistentFailClosedVerified,
        )
    }

    @Test
    fun serviceLossRemovesSessionFailClosedClaim() {
        val before = VpnRuntimeSnapshot(serviceRunning = true, captureEstablished = true)
        val after = before.copy(serviceRunning = false, captureEstablished = false)

        assertTrue(VpnEnforcementPolicy.evaluate(before).sessionFailClosedVerified)
        assertFalse(VpnEnforcementPolicy.evaluate(after).sessionFailClosedVerified)
    }

    @Test
    fun v03HasNoForwardingDisposition() {
        assertFalse(TrafficDisposition.entries.any { it.name.contains("FORWARD") })
    }
}
