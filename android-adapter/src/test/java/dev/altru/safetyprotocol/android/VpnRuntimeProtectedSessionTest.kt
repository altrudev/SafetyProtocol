package dev.altru.safetyprotocol.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Test

class VpnRuntimeProtectedSessionTest {
    @After
    fun reset() {
        SafetyProtocolVpnRuntime.reset()
    }

    @Test
    fun freshDerivedReadinessCanPromoteTunnelEvidence() {
        SafetyProtocolVpnRuntime.update {
            it.copy(serviceRunning = true, captureEstablished = true, osVpnTransportObserved = true)
        }
        SafetyProtocolVpnRuntime.updateProtectedSession(
            TransportSessionReadiness(
                authenticatedEstablishment = true,
                freshLiveness = true,
                protectedSessionReady = true,
                validUntilMs = 1_000,
                forwardingAuthorized = false,
            ),
        )

        assertTrue(SafetyProtocolVpnRuntime.evidence(nowMs = 500).protectedTunnelReady)
    }

    @Test
    fun staleReadinessCannotPromoteTunnelEvidence() {
        SafetyProtocolVpnRuntime.update {
            it.copy(serviceRunning = true, captureEstablished = true, osVpnTransportObserved = true)
        }
        SafetyProtocolVpnRuntime.updateProtectedSession(
            TransportSessionReadiness(
                authenticatedEstablishment = true,
                freshLiveness = false,
                protectedSessionReady = false,
                validUntilMs = null,
                forwardingAuthorized = false,
            ),
        )

        assertFalse(SafetyProtocolVpnRuntime.evidence(nowMs = 500).protectedTunnelReady)
    }

    @Test
    fun clearingSessionImmediatelyRemovesReadiness() {
        SafetyProtocolVpnRuntime.update {
            it.copy(serviceRunning = true, captureEstablished = true, osVpnTransportObserved = true)
        }
        SafetyProtocolVpnRuntime.updateProtectedSession(
            TransportSessionReadiness(true, true, true, 1_000, false),
        )
        assertTrue(SafetyProtocolVpnRuntime.evidence(nowMs = 500).protectedTunnelReady)

        SafetyProtocolVpnRuntime.clearProtectedSession()
        assertFalse(SafetyProtocolVpnRuntime.evidence(nowMs = 500).protectedTunnelReady)
    }

    @Test
    fun storedReadinessExpiresWithoutCleanupCallback() {
        SafetyProtocolVpnRuntime.update {
            it.copy(serviceRunning = true, captureEstablished = true, osVpnTransportObserved = true)
        }
        SafetyProtocolVpnRuntime.updateProtectedSession(
            TransportSessionReadiness(true, true, true, 1_000, false),
        )
        assertTrue(SafetyProtocolVpnRuntime.evidence(nowMs = 999).protectedTunnelReady)
        assertFalse(SafetyProtocolVpnRuntime.evidence(nowMs = 1_000).protectedTunnelReady)
    }


    @Test
    fun runtimeReadinessCanPromoteRustPolicyOnlyWhileFresh() {
        val wifi = RawAndroidNetworkObservation(
            transport = Transport.WIFI,
            userApproved = false,
            ssidKnown = false,
            validatedInternet = true,
            captivePortal = false,
            security = WifiSecurity.WPA2_OR_BETTER,
            contradictoryEvidence = false,
            hardDrift = false,
        )
        SafetyProtocolVpnRuntime.update {
            it.copy(
                serviceRunning = true,
                captureEstablished = true,
                osVpnTransportObserved = true,
                transportReadiness = TransportSessionReadiness(true, true, true, 1_000, false),
            )
        }

        val fresh = SafetyProtocolNative.evaluate(wifi, SafetyProtocolVpnRuntime.evidence(nowMs = 999))
        val expired = SafetyProtocolNative.evaluate(wifi, SafetyProtocolVpnRuntime.evidence(nowMs = 1_000))

        assertTrue(fresh.authority == CoreConnectivityAuthority.PROTECTED_TRANSPORT)
        assertTrue(expired.authority == CoreConnectivityAuthority.DENIED)
    }

}
