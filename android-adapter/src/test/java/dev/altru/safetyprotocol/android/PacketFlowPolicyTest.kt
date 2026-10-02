package dev.altru.safetyprotocol.android

import org.junit.Assert.assertEquals
import org.junit.Test

class PacketFlowPolicyTest {
    @Test
    fun publicTcpIsEligibleForFurtherPolicy() {
        val m = metadata(DestinationScope.PUBLIC, PacketTransportProtocol.TCP, 443)
        assertEquals(PacketFlowDisposition.ALLOW_TO_FORWARDING_GATE, PacketFlowPolicy.evaluate(m).disposition)
    }

    @Test
    fun privateDestinationIsDeniedWithoutLocalAuthority() {
        val m = metadata(DestinationScope.LOCAL_PRIVATE, PacketTransportProtocol.TCP, 443)
        assertEquals(PacketFlowReason.LOCAL_DESTINATION_NOT_AUTHORIZED, PacketFlowPolicy.evaluate(m).reason)
    }

    @Test
    fun loopbackLinkLocalAndMulticastAreDenied() {
        listOf(DestinationScope.LOOPBACK, DestinationScope.LINK_LOCAL, DestinationScope.MULTICAST).forEach {
            assertEquals(PacketFlowDisposition.DENY, PacketFlowPolicy.evaluate(metadata(it, PacketTransportProtocol.UDP, 53)).disposition)
        }
    }

    @Test
    fun dnsIsRecognizedButNotGivenDirectDnsAuthority() {
        val decision = PacketFlowPolicy.evaluate(metadata(DestinationScope.PUBLIC, PacketTransportProtocol.UDP, 53))
        assertEquals(PacketFlowDisposition.ALLOW_TO_FORWARDING_GATE, decision.disposition)
        assertEquals(PacketFlowReason.PUBLIC_DNS_OVER_PROTECTED_TRANSPORT, decision.reason)
    }

    @Test
    fun unsupportedProtocolIsDenied() {
        val m = PacketMetadata(IpVersion.IPV4, PacketTransportProtocol.OTHER, DestinationScope.PUBLIC, null, 40)
        assertEquals(PacketFlowReason.UNSUPPORTED_TRANSPORT_PROTOCOL, PacketFlowPolicy.evaluate(m).reason)
    }

    private fun metadata(scope: DestinationScope, protocol: PacketTransportProtocol, port: Int?) =
        PacketMetadata(IpVersion.IPV4, protocol, scope, port, 40)
}
