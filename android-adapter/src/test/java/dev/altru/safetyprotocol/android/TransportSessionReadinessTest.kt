package dev.altru.safetyprotocol.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportSessionReadinessTest {
    private val authenticated = ProtectedTransportEvidence(
        socketProtectedFromVpn = true,
        tlsHandshakeComplete = true,
        hostnameVerified = true,
        publicKeyPinVerified = true,
        sessionEstablished = true,
        localSocketOpen = true,
    )

    @Test
    fun authenticationWithoutFreshLivenessIsNotReady() {
        val readiness = TransportSessionReadiness.evaluate(
            authenticated,
            TransportLivenessSnapshot(false, null, null),
        )
        assertFalse(readiness.protectedSessionReady)
        assertFalse(readiness.forwardingAuthorized)
    }

    @Test
    fun freshLivenessWithoutAuthenticationIsNotReady() {
        val readiness = TransportSessionReadiness.evaluate(
            ProtectedTransportEvidence(),
            TransportLivenessSnapshot(true, 100, null),
        )
        assertFalse(readiness.protectedSessionReady)
    }

    @Test
    fun authenticationPlusFreshLivenessCanEstablishReadinessButNotForwarding() {
        val readiness = TransportSessionReadiness.evaluate(
            authenticated,
            TransportLivenessSnapshot(true, 100, null),
        )
        assertTrue(readiness.protectedSessionReady)
        assertFalse(readiness.forwardingAuthorized)
    }
}
