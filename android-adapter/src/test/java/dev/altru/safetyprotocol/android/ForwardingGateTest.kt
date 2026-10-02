package dev.altru.safetyprotocol.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ForwardingGateTest {
    private val endpoint = ProtectedTransportEndpoint.fromHexPin(
        host = "relay.example",
        port = 443,
        sha256Hex = "11".repeat(32),
    )

    private val readiness = TransportSessionReadiness(
        authenticatedEstablishment = true,
        freshLiveness = true,
        protectedSessionReady = true,
        validUntilMs = 1_000,
        forwardingAuthorized = false,
    )

    private val runtime = VpnRuntimeSnapshot(
        serviceRunning = true,
        captureEstablished = true,
        osVpnTransportObserved = true,
        transportReadiness = readiness,
    )

    private val decision = CoreConnectivityDecision(
        authority = CoreConnectivityAuthority.PROTECTED_TRANSPORT,
        reason = CoreDecisionReason.PROTECTED_TRANSPORT_ONLY,
        effective = CoreAuthority(
            transport = true,
            read = false,
            write = false,
            execute = false,
            localNetwork = false,
            directDns = false,
            credentialUse = false,
            dataEgress = true,
        ),
        protectedTunnelRequired = true,
    )

    private val data = TransportFrame(
        type = TransportFrameType.DATA,
        sequence = 10,
        payload = byteArrayOf(0x45, 0x00, 0x00, 0x14),
    )

    @Test
    fun validEvidenceCanBecomeEligibleButNotActive() {
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, endpoint, data, nowMs = 500)
        assertEquals(ForwardingGateDisposition.ELIGIBLE, result.disposition)
        assertTrue(result.eligible)
        assertFalse(result.forwardingActive)
    }

    @Test
    fun missingCaptureDrops() {
        val result = ForwardingGate.evaluate(
            runtime.copy(captureEstablished = false), decision, endpoint, endpoint, data, nowMs = 500,
        )
        assertEquals(ForwardingGateReason.CAPTURE_NOT_ESTABLISHED, result.reason)
        assertFalse(result.eligible)
    }

    @Test
    fun missingOsVpnCorroborationDrops() {
        val result = ForwardingGate.evaluate(
            runtime.copy(osVpnTransportObserved = false), decision, endpoint, endpoint, data, nowMs = 500,
        )
        assertEquals(ForwardingGateReason.OS_VPN_NOT_CORROBORATED, result.reason)
    }

    @Test
    fun staleOrUnauthenticatedReadinessDrops() {
        val stale = TransportSessionReadiness(
            authenticatedEstablishment = true,
            freshLiveness = false,
            protectedSessionReady = false,
            validUntilMs = null,
            forwardingAuthorized = false,
        )
        val result = ForwardingGate.evaluate(
            runtime.copy(transportReadiness = stale), decision, endpoint, endpoint, data, nowMs = 500,
        )
        assertEquals(ForwardingGateReason.PROTECTED_SESSION_NOT_READY, result.reason)
    }

    @Test
    fun wrongCoreAuthorityDrops() {
        val denied = decision.copy(authority = CoreConnectivityAuthority.DENIED)
        val result = ForwardingGate.evaluate(runtime, denied, endpoint, endpoint, data, nowMs = 500)
        assertEquals(ForwardingGateReason.POLICY_NOT_AUTHORIZED, result.reason)
    }

    @Test
    fun overPrivilegedCoreAuthorityDrops() {
        val over = decision.copy(effective = decision.effective.copy(localNetwork = true))
        val result = ForwardingGate.evaluate(runtime, over, endpoint, endpoint, data, nowMs = 500)
        assertEquals(ForwardingGateReason.AUTHORITY_SCOPE_MISMATCH, result.reason)
    }

    @Test
    fun wrongEndpointBindingDrops() {
        val other = ProtectedTransportEndpoint.fromHexPin(
            host = "other.example", port = 443, sha256Hex = "11".repeat(32),
        )
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, other, data, nowMs = 500)
        assertEquals(ForwardingGateReason.ENDPOINT_BINDING_MISMATCH, result.reason)
    }

    @Test
    fun wrongPinBindingDrops() {
        val otherPin = ProtectedTransportEndpoint.fromHexPin(
            host = "relay.example", port = 443, sha256Hex = "22".repeat(32),
        )
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, otherPin, data, nowMs = 500)
        assertEquals(ForwardingGateReason.ENDPOINT_BINDING_MISMATCH, result.reason)
    }

    @Test
    fun nonDataFrameDrops() {
        val ping = TransportFrame(TransportFrameType.PING, 10, ByteArray(TransportLivenessTracker.NONCE_BYTES))
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, endpoint, ping, nowMs = 500)
        assertEquals(ForwardingGateReason.NOT_DATA_FRAME, result.reason)
    }

    @Test
    fun emptyDataFrameDrops() {
        val empty = TransportFrame(TransportFrameType.DATA, 10, ByteArray(0))
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, endpoint, empty, nowMs = 500)
        assertEquals(ForwardingGateReason.EMPTY_DATA, result.reason)
    }

    @Test
    fun stoppedServiceDrops() {
        val result = ForwardingGate.evaluate(
            runtime.copy(serviceRunning = false), decision, endpoint, endpoint, data, nowMs = 500,
        )
        assertEquals(ForwardingGateReason.SERVICE_NOT_RUNNING, result.reason)
    }


    @Test
    fun expiredReadinessDropsEvenIfStoredFlagsRemainTrue() {
        val result = ForwardingGate.evaluate(
            runtime, decision, endpoint, endpoint, data, nowMs = 1_000,
        )
        assertEquals(ForwardingGateReason.PROTECTED_SESSION_NOT_READY, result.reason)
    }

}
