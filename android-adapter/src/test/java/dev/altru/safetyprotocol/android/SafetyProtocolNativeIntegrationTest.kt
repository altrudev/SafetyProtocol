package dev.altru.safetyprotocol.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SafetyProtocolNativeIntegrationTest {
    private fun wifi(
        validated: Boolean = true,
        captive: Boolean = false,
        contradiction: Boolean = false,
        hardDrift: Boolean = false,
    ) = RawAndroidNetworkObservation(
        transport = Transport.WIFI,
        userApproved = true,
        ssidKnown = true,
        validatedInternet = validated,
        captivePortal = captive,
        security = WifiSecurity.WPA2_OR_BETTER,
        contradictoryEvidence = contradiction,
        hardDrift = hardDrift,
    )

    private fun evidence(
        capture: Boolean = true,
        osObserved: Boolean = true,
        authenticated: Boolean = true,
    ) = TunnelEnforcementEvidence(
        localCaptureEstablished = capture,
        osVpnTransportObserved = osObserved,
        protectedSessionAuthenticated = authenticated,
        sessionFailClosedVerified = capture,
        persistentFailClosedVerified = false,
    )

    @Test
    fun nativeAbiIsExpectedVersion() {
        assertEquals(SafetyProtocolNative.EXPECTED_ABI_VERSION, SafetyProtocolNative.nativeAbiVersion())
    }

    @Test
    fun androidClaimsCannotPromoteWifiToTrusted() {
        val decision = SafetyProtocolNative.evaluate(wifi(), evidence())
        assertEquals(CoreConnectivityAuthority.PROTECTED_TRANSPORT, decision.authority)
        assertTrue(decision.effective.transport)
        assertTrue(decision.effective.dataEgress)
        assertFalse(decision.effective.localNetwork)
        assertFalse(decision.effective.directDns)
        assertTrue(decision.protectedTunnelRequired)
    }

    @Test
    fun localCaptureWithoutAuthenticatedSessionFailsClosed() {
        val decision = SafetyProtocolNative.evaluate(wifi(), evidence(authenticated = false))
        assertEquals(CoreConnectivityAuthority.DENIED, decision.authority)
        assertEquals(CoreDecisionReason.PROTECTED_TRANSPORT_UNAVAILABLE, decision.reason)
    }

    @Test
    fun osVpnObservationIsRequiredForProtectedReadiness() {
        val decision = SafetyProtocolNative.evaluate(wifi(), evidence(osObserved = false))
        assertEquals(CoreConnectivityAuthority.DENIED, decision.authority)
    }

    @Test
    fun captiveAndUnvalidatedWifiFailClosedInNativeCore() {
        assertEquals(
            CoreConnectivityAuthority.DENIED,
            SafetyProtocolNative.evaluate(wifi(captive = true), evidence()).authority,
        )
        assertEquals(
            CoreConnectivityAuthority.DENIED,
            SafetyProtocolNative.evaluate(wifi(validated = false), evidence()).authority,
        )
    }

    @Test
    fun cellularNeedsExplicitBudgetedFallback() {
        val cellular = RawAndroidNetworkObservation(
            transport = Transport.CELLULAR,
            userApproved = false,
            ssidKnown = false,
            validatedInternet = true,
            captivePortal = false,
            security = WifiSecurity.NOT_APPLICABLE,
            contradictoryEvidence = false,
            hardDrift = false,
        )
        assertEquals(
            CoreConnectivityAuthority.DENIED,
            SafetyProtocolNative.evaluate(cellular, evidence(capture = false, osObserved = false, authenticated = false)).authority,
        )
        assertEquals(
            CoreConnectivityAuthority.CELLULAR_FALLBACK,
            SafetyProtocolNative.evaluate(
                cellular,
                evidence(capture = false, osObserved = false, authenticated = false),
                allowCellularFallback = true,
                remainingCellularBudgetMb = 5,
            ).authority,
        )
    }
}
