package dev.altru.safetyprotocol.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidNetworkObservationPrivacyTest {
    @Test
    fun mapperNeverAuthenticatesFromAndroidObservation() {
        val raw = RawAndroidNetworkObservation(
            transport = Transport.WIFI,
            userApproved = true,
            ssidKnown = true,
            validatedInternet = true,
            captivePortal = false,
            security = WifiSecurity.WPA2_OR_BETTER,
            contradictoryEvidence = false,
            hardDrift = false,
        )
        val mapped = AndroidNetworkObservationMapper.map(raw)
        assertFalse(mapped.authenticatedIdentity)
        assertTrue(mapped.familiarityObserved)
    }

    @Test
    fun publicWifiNeverGetsLocalOrDirectDnsAuthority() {
        val raw = RawAndroidNetworkObservation(
            transport = Transport.WIFI,
            userApproved = false,
            ssidKnown = false,
            validatedInternet = true,
            captivePortal = false,
            security = WifiSecurity.OPEN,
            contradictoryEvidence = false,
            hardDrift = false,
        )
        val mapped = AndroidNetworkObservationMapper.map(raw)
        assertFalse(mapped.localNetworkAuthority)
        assertFalse(mapped.directDnsAuthority)
    }
}
