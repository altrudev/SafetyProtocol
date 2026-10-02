package dev.altru.safetyprotocol.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidNetworkObservationMapperTest {
    private fun publicWifi(
        userApproved: Boolean = false,
        ssidKnown: Boolean = false,
        validated: Boolean = true,
        captive: Boolean = false,
        contradiction: Boolean = false,
        hardDrift: Boolean = false,
    ) = RawAndroidNetworkObservation(
        transport = Transport.WIFI,
        userApproved = userApproved,
        ssidKnown = ssidKnown,
        validatedInternet = validated,
        captivePortal = captive,
        security = WifiSecurity.OPEN,
        contradictoryEvidence = contradiction,
        hardDrift = hardDrift,
    )

    @Test
    fun ssidFamiliarityNeverAuthenticatesIdentity() {
        val mapped = AndroidNetworkObservationMapper.map(publicWifi(ssidKnown = true))
        assertFalse(mapped.authenticatedIdentity)
        assertTrue(mapped.familiarityObserved)
    }

    @Test
    fun wifiMapsToUntrustedTransportAndRequiresProtection() {
        val mapped = AndroidNetworkObservationMapper.map(publicWifi())
        assertEquals(NetworkClass.PUBLIC_UNTRUSTED, mapped.networkClass)
        assertTrue(mapped.protectedTunnelRequired)
        assertFalse(mapped.localNetworkAuthority)
        assertFalse(mapped.directDnsAuthority)
        assertEquals(AdapterRecommendation.FORWARD_TO_POLICY, mapped.recommendation)
    }

    @Test
    fun captivePortalCannotBecomeTrusted() {
        val mapped = AndroidNetworkObservationMapper.map(
            publicWifi(userApproved = true, ssidKnown = true, validated = false, captive = true),
        )
        assertEquals(NetworkClass.PUBLIC_UNTRUSTED, mapped.networkClass)
        assertFalse(mapped.authenticatedIdentity)
    }

    @Test
    fun hardDriftForcesDenyRecommendation() {
        val mapped = AndroidNetworkObservationMapper.map(publicWifi(hardDrift = true))
        assertEquals(AdapterRecommendation.DENY, mapped.recommendation)
    }

    @Test
    fun contradictionForcesDenyRecommendation() {
        val mapped = AndroidNetworkObservationMapper.map(publicWifi(contradiction = true))
        assertEquals(AdapterRecommendation.DENY, mapped.recommendation)
    }

    @Test
    fun cellularIsFallbackNotTrustedNetwork() {
        val raw = RawAndroidNetworkObservation(
            transport = Transport.CELLULAR,
            userApproved = false,
            ssidKnown = false,
            validatedInternet = true,
            captivePortal = false,
            security = WifiSecurity.NOT_APPLICABLE,
            contradictoryEvidence = false,
            hardDrift = false,
        )
        val mapped = AndroidNetworkObservationMapper.map(raw)
        assertEquals(NetworkClass.CELLULAR_FALLBACK, mapped.networkClass)
        assertFalse(mapped.authenticatedIdentity)
    }
}
