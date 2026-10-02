package dev.altru.safetyprotocol.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidNetworkObservationMapperTest {
    @Test
    fun ssidFamiliarityNeverAuthenticatesIdentity() {
        val raw = RawAndroidNetworkObservation(
            transport = Transport.WIFI,
            userApproved = false,
            ssidKnown = true,
            validatedInternet = true,
            captivePortal = false,
            security = WifiSecurity.WPA2_OR_BETTER,
            protectedTunnelReady = true,
            contradictoryEvidence = false,
            hardDrift = false,
        )

        val mapped = AndroidNetworkObservationMapper.map(raw)
        assertFalse(mapped.authenticatedIdentity)
        assertTrue(mapped.familiarityObserved)
    }

    @Test
    fun openWifiMapsToUntrustedTransport() {
        val raw = RawAndroidNetworkObservation(
            transport = Transport.WIFI,
            userApproved = false,
            ssidKnown = false,
            validatedInternet = true,
            captivePortal = false,
            security = WifiSecurity.OPEN,
            protectedTunnelReady = true,
            contradictoryEvidence = false,
            hardDrift = false,
        )

        val mapped = AndroidNetworkObservationMapper.map(raw)
        assertEquals(NetworkClass.PUBLIC_UNTRUSTED, mapped.networkClass)
        assertTrue(mapped.protectedTunnelRequired)
        assertFalse(mapped.localNetworkAuthority)
        assertFalse(mapped.directDnsAuthority)
    }

    @Test
    fun captivePortalCannotBecomeTrusted() {
        val raw = RawAndroidNetworkObservation(
            transport = Transport.WIFI,
            userApproved = true,
            ssidKnown = true,
            validatedInternet = false,
            captivePortal = true,
            security = WifiSecurity.WPA2_OR_BETTER,
            protectedTunnelReady = true,
            contradictoryEvidence = false,
            hardDrift = false,
        )

        val mapped = AndroidNetworkObservationMapper.map(raw)
        assertEquals(NetworkClass.PUBLIC_UNTRUSTED, mapped.networkClass)
        assertFalse(mapped.authenticatedIdentity)
    }

    @Test
    fun hardDriftForcesDenyRecommendation() {
        val raw = RawAndroidNetworkObservation(
            transport = Transport.WIFI,
            userApproved = true,
            ssidKnown = true,
            validatedInternet = true,
            captivePortal = false,
            security = WifiSecurity.WPA2_OR_BETTER,
            protectedTunnelReady = true,
            contradictoryEvidence = false,
            hardDrift = true,
        )

        val mapped = AndroidNetworkObservationMapper.map(raw)
        assertEquals(AdapterRecommendation.DENY, mapped.recommendation)
    }

    @Test
    fun missingProtectedTunnelDeniesPublicWifi() {
        val raw = RawAndroidNetworkObservation(
            transport = Transport.WIFI,
            userApproved = false,
            ssidKnown = false,
            validatedInternet = true,
            captivePortal = false,
            security = WifiSecurity.OPEN,
            protectedTunnelReady = false,
            contradictoryEvidence = false,
            hardDrift = false,
        )

        val mapped = AndroidNetworkObservationMapper.map(raw)
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
            protectedTunnelReady = false,
            contradictoryEvidence = false,
            hardDrift = false,
        )

        val mapped = AndroidNetworkObservationMapper.map(raw)
        assertEquals(NetworkClass.CELLULAR_FALLBACK, mapped.networkClass)
        assertFalse(mapped.authenticatedIdentity)
    }
}
