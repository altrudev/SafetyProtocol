package dev.altru.safetyprotocol.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectedTransportStateTest {
    @Test
    fun authenticatedRequiresEveryBoundary() {
        val evidence = ProtectedTransportEvidence(
            socketProtectedFromVpn = true,
            tlsHandshakeComplete = true,
            hostnameVerified = true,
            publicKeyPinVerified = true,
            sessionEstablished = true,
            localSocketOpen = true,
        )
        assertTrue(evidence.authenticated)
    }

    @Test
    fun unprotectedSocketCannotAuthenticate() {
        val evidence = fullyVerified().copy(socketProtectedFromVpn = false)
        assertFalse(evidence.authenticated)
    }

    @Test
    fun missingHostnameVerificationCannotAuthenticate() {
        val evidence = fullyVerified().copy(hostnameVerified = false)
        assertFalse(evidence.authenticated)
    }

    @Test
    fun pinMismatchCannotAuthenticate() {
        val evidence = fullyVerified().copy(publicKeyPinVerified = false)
        assertFalse(evidence.authenticated)
    }

    @Test
    fun deadSessionCannotAuthenticate() {
        val evidence = fullyVerified().copy(localSocketOpen = false)
        assertFalse(evidence.authenticated)
    }

    @Test
    fun transportStateNeverImpliesForwarding() {
        val state = ProtectedTransportState.fromEvidence(fullyVerified())
        assertEquals(ProtectedTransportPhase.AUTHENTICATED, state.phase)
        assertFalse(state.forwardingAuthorized)
    }

    private fun fullyVerified() = ProtectedTransportEvidence(
        socketProtectedFromVpn = true,
        tlsHandshakeComplete = true,
        hostnameVerified = true,
        publicKeyPinVerified = true,
        sessionEstablished = true,
            localSocketOpen = true,
    )
}
