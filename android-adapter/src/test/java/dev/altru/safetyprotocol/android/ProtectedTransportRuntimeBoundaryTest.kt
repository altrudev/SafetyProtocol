package dev.altru.safetyprotocol.android

import org.junit.Assert.assertFalse
import org.junit.Test

class ProtectedTransportRuntimeBoundaryTest {
    @Test
    fun v04TransportEstablishmentDoesNotPromoteVpnRuntimeReadiness() {
        val runtimeEvidence = SafetyProtocolVpnRuntime.evidence()
        assertFalse(runtimeEvidence.protectedTunnelReady)
    }
}
