package dev.altru.safetyprotocol.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SafetyProtocolNativeIntegrationTest {
    private fun wifi(
        validated: Boolean = true,
        captive: Boolean = false,
        tunnel: Boolean = true,
        contradiction: Boolean = false,
        hardDrift: Boolean = false,
    ) = RawAndroidNetworkObservation(
        transport = Transport.WIFI,
        userApproved = true,
        ssidKnown = true,
        validatedInternet = validated,
        captivePortal = captive,
        security = WifiSecurity.WPA2_OR_BETTER,
        protectedTunnelReady = tunnel,
        contradictoryEvidence = contradiction,
        hardDrift = hardDrift,
    )

    @Test
    fun nativeAbiIsExpectedVersion() {
        assertEquals(SafetyProtocolNative.EXPECTED_ABI_VERSION, SafetyProtocolNative.nativeAbiVersion())
    }

    @Test
    fun androidClaimsCannotPromoteWifiToTrusted() {
        val decision = SafetyProtocolNative.evaluate(wifi())
        assertEquals(CoreConnectivityAuthority.PROTECTED_TRANSPORT, decision.authority)
        assertTrue(decision.effective.transport)
        assertTrue(decision.effective.dataEgress)
        assertFalse(decision.effective.localNetwork)
        assertFalse(decision.effective.directDns)
        assertTrue(decision.protectedTunnelRequired)
    }

    @Test
    fun tunnelLossFailsClosedInNativeCore() {
        val decision = SafetyProtocolNative.evaluate(wifi(tunnel = false))
        assertEquals(CoreConnectivityAuthority.DENIED, decision.authority)
        assertEquals(CoreDecisionReason.PROTECTED_TRANSPORT_UNAVAILABLE, decision.reason)
    }

    @Test
    fun captiveAndUnvalidatedWifiFailClosedInNativeCore() {
        assertEquals(CoreConnectivityAuthority.DENIED, SafetyProtocolNative.evaluate(wifi(captive = true)).authority)
        assertEquals(CoreConnectivityAuthority.DENIED, SafetyProtocolNative.evaluate(wifi(validated = false)).authority)
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
            protectedTunnelReady = false,
            contradictoryEvidence = false,
            hardDrift = false,
        )
        assertEquals(CoreConnectivityAuthority.DENIED, SafetyProtocolNative.evaluate(cellular).authority)
        assertEquals(
            CoreConnectivityAuthority.CELLULAR_FALLBACK,
            SafetyProtocolNative.evaluate(cellular, allowCellularFallback = true, remainingCellularBudgetMb = 5).authority,
        )
    }
}
