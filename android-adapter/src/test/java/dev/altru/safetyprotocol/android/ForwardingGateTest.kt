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

    private val allowPublic = DestinationPolicy(
        listOf(DestinationRule.allow("8.8.8.0/24")),
    )

    private val denyAll = DestinationPolicy(emptyList())

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
        payload = publicIpv4TcpPacket(443),
    )

    @Test
    fun validEvidenceCanBecomeEligibleButNotActive() {
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, endpoint, allowPublic, data, nowMs = 500)
        assertEquals(ForwardingGateDisposition.ELIGIBLE, result.disposition)
        assertTrue(result.eligible)
        assertFalse(result.forwardingActive)
    }

    @Test
    fun missingCaptureDrops() {
        val result = ForwardingGate.evaluate(
            runtime.copy(captureEstablished = false), decision, endpoint, endpoint, allowPublic, data, nowMs = 500,
        )
        assertEquals(ForwardingGateReason.CAPTURE_NOT_ESTABLISHED, result.reason)
        assertFalse(result.eligible)
    }

    @Test
    fun missingOsVpnCorroborationDrops() {
        val result = ForwardingGate.evaluate(
            runtime.copy(osVpnTransportObserved = false), decision, endpoint, endpoint, allowPublic, data, nowMs = 500,
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
            runtime.copy(transportReadiness = stale), decision, endpoint, endpoint, allowPublic, data, nowMs = 500,
        )
        assertEquals(ForwardingGateReason.PROTECTED_SESSION_NOT_READY, result.reason)
    }

    @Test
    fun wrongCoreAuthorityDrops() {
        val denied = decision.copy(authority = CoreConnectivityAuthority.DENIED)
        val result = ForwardingGate.evaluate(runtime, denied, endpoint, endpoint, allowPublic, data, nowMs = 500)
        assertEquals(ForwardingGateReason.POLICY_NOT_AUTHORIZED, result.reason)
    }

    @Test
    fun overPrivilegedCoreAuthorityDrops() {
        val over = decision.copy(effective = decision.effective.copy(localNetwork = true))
        val result = ForwardingGate.evaluate(runtime, over, endpoint, endpoint, allowPublic, data, nowMs = 500)
        assertEquals(ForwardingGateReason.AUTHORITY_SCOPE_MISMATCH, result.reason)
    }

    @Test
    fun wrongEndpointBindingDrops() {
        val other = ProtectedTransportEndpoint.fromHexPin(
            host = "other.example", port = 443, sha256Hex = "11".repeat(32),
        )
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, other, allowPublic, data, nowMs = 500)
        assertEquals(ForwardingGateReason.ENDPOINT_BINDING_MISMATCH, result.reason)
    }

    @Test
    fun wrongPinBindingDrops() {
        val otherPin = ProtectedTransportEndpoint.fromHexPin(
            host = "relay.example", port = 443, sha256Hex = "22".repeat(32),
        )
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, otherPin, allowPublic, data, nowMs = 500)
        assertEquals(ForwardingGateReason.ENDPOINT_BINDING_MISMATCH, result.reason)
    }

    @Test
    fun nonDataFrameDrops() {
        val ping = TransportFrame(TransportFrameType.PING, 10, ByteArray(TransportLivenessTracker.NONCE_BYTES))
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, endpoint, allowPublic, ping, nowMs = 500)
        assertEquals(ForwardingGateReason.NOT_DATA_FRAME, result.reason)
    }

    @Test
    fun emptyDataFrameDrops() {
        val empty = TransportFrame(TransportFrameType.DATA, 10, ByteArray(0))
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, endpoint, allowPublic, empty, nowMs = 500)
        assertEquals(ForwardingGateReason.EMPTY_DATA, result.reason)
    }

    @Test
    fun stoppedServiceDrops() {
        val result = ForwardingGate.evaluate(
            runtime.copy(serviceRunning = false), decision, endpoint, endpoint, allowPublic, data, nowMs = 500,
        )
        assertEquals(ForwardingGateReason.SERVICE_NOT_RUNNING, result.reason)
    }


    @Test
    fun expiredReadinessDropsEvenIfStoredFlagsRemainTrue() {
        val result = ForwardingGate.evaluate(
            runtime, decision, endpoint, endpoint, allowPublic, data, nowMs = 1_000,
        )
        assertEquals(ForwardingGateReason.PROTECTED_SESSION_NOT_READY, result.reason)
    }

    @Test
    fun publicPacketWithoutExplicitDestinationAllowDrops() {
        val result = ForwardingGate.evaluate(
            runtime,
            decision,
            endpoint,
            endpoint,
            denyAll,
            data,
            nowMs = 500,
        )
        assertEquals(ForwardingGateReason.DESTINATION_POLICY_NOT_AUTHORIZED, result.reason)
        assertFalse(result.eligible)
    }

    @Test
    fun moreSpecificDestinationDenyOverridesBroaderAllowAtGate() {
        val policy = DestinationPolicy(
            listOf(
                DestinationRule.allow("8.0.0.0/8"),
                DestinationRule.deny("8.8.8.0/24"),
            ),
        )
        val result = ForwardingGate.evaluate(
            runtime,
            decision,
            endpoint,
            endpoint,
            policy,
            data,
            nowMs = 500,
        )
        assertEquals(ForwardingGateReason.DESTINATION_POLICY_NOT_AUTHORIZED, result.reason)
        assertFalse(result.eligible)
    }

    private fun publicIpv4TcpPacket(destinationPort: Int): ByteArray {
        val packet = ByteArray(40)
        packet[0] = 0x45
        packet[2] = 0
        packet[3] = 40
        packet[8] = 64
        packet[9] = 6
        packet[12] = 10
        packet[13] = 0
        packet[14] = 0
        packet[15] = 2
        packet[16] = 8
        packet[17] = 8
        packet[18] = 8
        packet[19] = 8
        packet[20] = 0x30
        packet[21] = 0x39
        packet[22] = (destinationPort ushr 8).toByte()
        packet[23] = destinationPort.toByte()
        packet[32] = 0x50
        return packet
    }

    @Test
    fun privateInnerDestinationDropsBeforeForwardingEligibility() {
        val payload = publicIpv4TcpPacket(443)
        payload[16] = 192.toByte()
        payload[17] = 168.toByte()
        payload[18] = 1
        payload[19] = 10
        val privateData = TransportFrame(TransportFrameType.DATA, 11, payload)
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, endpoint, allowPublic, privateData, nowMs = 500)
        assertEquals(ForwardingGateReason.DATA_FLOW_NOT_AUTHORIZED, result.reason)
        assertEquals(PacketFlowReason.LOCAL_DESTINATION_NOT_AUTHORIZED, result.packetFlowReason)
        assertFalse(result.eligible)
    }

    @Test
    fun malformedInnerPacketDropsBeforeForwardingEligibility() {
        val malformed = TransportFrame(TransportFrameType.DATA, 11, byteArrayOf(0x45, 0x00))
        val result = ForwardingGate.evaluate(runtime, decision, endpoint, endpoint, allowPublic, malformed, nowMs = 500)
        assertEquals(ForwardingGateReason.PACKET_PARSE_REJECTED, result.reason)
        assertFalse(result.eligible)
    }

}
