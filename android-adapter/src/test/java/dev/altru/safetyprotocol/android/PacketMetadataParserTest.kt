package dev.altru.safetyprotocol.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketMetadataParserTest {

    @Test
    fun independentlyRejectsOversizedPacket() {
        val result = PacketMetadataParser.parse(ByteArray(PacketMetadataParser.MAX_PACKET_BYTES + 1))
        assertEquals(PacketParseFailure.PACKET_TOO_LARGE, (result as PacketParseResult.Rejected).failure)
    }

    @Test
    fun parsesMinimalIpv4TcpDestination() {
        val packet = ipv4Packet(protocol = 6, destination = byteArrayOf(8, 8, 8, 8), destinationPort = 443)
        val result = PacketMetadataParser.parse(packet)
        assertTrue(result is PacketParseResult.Parsed)
        val metadata = (result as PacketParseResult.Parsed).metadata
        assertEquals(IpVersion.IPV4, metadata.ipVersion)
        assertEquals(PacketTransportProtocol.TCP, metadata.protocol)
        assertEquals(443, metadata.destinationPort)
        assertEquals(DestinationScope.PUBLIC, metadata.destinationScope)
    }

    @Test
    fun parsesMinimalIpv4UdpDestination() {
        val packet = ipv4Packet(protocol = 17, destination = byteArrayOf(1, 1, 1, 1), destinationPort = 53)
        val metadata = (PacketMetadataParser.parse(packet) as PacketParseResult.Parsed).metadata
        assertEquals(PacketTransportProtocol.UDP, metadata.protocol)
        assertEquals(53, metadata.destinationPort)
    }

    @Test
    fun privateIpv4IsClassifiedLocalPrivate() {
        val packet = ipv4Packet(protocol = 6, destination = byteArrayOf(192.toByte(), 168.toByte(), 1, 10), destinationPort = 443)
        val metadata = (PacketMetadataParser.parse(packet) as PacketParseResult.Parsed).metadata
        assertEquals(DestinationScope.LOCAL_PRIVATE, metadata.destinationScope)
    }

    @Test
    fun linkLocalIpv4IsNotPublic() {
        val packet = ipv4Packet(protocol = 6, destination = byteArrayOf(169.toByte(), 254.toByte(), 1, 2), destinationPort = 443)
        val metadata = (PacketMetadataParser.parse(packet) as PacketParseResult.Parsed).metadata
        assertEquals(DestinationScope.LINK_LOCAL, metadata.destinationScope)
    }

    @Test
    fun loopbackIpv4IsNotPublic() {
        val packet = ipv4Packet(protocol = 6, destination = byteArrayOf(127, 0, 0, 1), destinationPort = 443)
        val metadata = (PacketMetadataParser.parse(packet) as PacketParseResult.Parsed).metadata
        assertEquals(DestinationScope.LOOPBACK, metadata.destinationScope)
    }

    @Test
    fun multicastIpv4IsNotPublic() {
        val packet = ipv4Packet(protocol = 17, destination = byteArrayOf(224.toByte(), 0, 0, 251.toByte()), destinationPort = 5353)
        val metadata = (PacketMetadataParser.parse(packet) as PacketParseResult.Parsed).metadata
        assertEquals(DestinationScope.MULTICAST, metadata.destinationScope)
    }

    @Test
    fun fragmentedIpv4FailsClosed() {
        val packet = ipv4Packet(protocol = 17, destination = byteArrayOf(8, 8, 8, 8), destinationPort = 53)
        packet[6] = 0x20
        val result = PacketMetadataParser.parse(packet)
        assertEquals(PacketParseFailure.FRAGMENTED_PACKET, (result as PacketParseResult.Rejected).failure)
    }

    @Test
    fun truncatedIpv4FailsClosed() {
        val packet = ipv4Packet(protocol = 6, destination = byteArrayOf(8, 8, 8, 8), destinationPort = 443)
        val result = PacketMetadataParser.parse(packet.copyOf(21))
        assertEquals(PacketParseFailure.TRUNCATED_PACKET, (result as PacketParseResult.Rejected).failure)
    }

    @Test
    fun parsesMinimalIpv6TcpDestination() {
        val destination = byteArrayOf(
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (0x88).toByte(), (0x88).toByte(),
        )
        val packet = ipv6Packet(nextHeader = 6, destination = destination, destinationPort = 443)
        val metadata = (PacketMetadataParser.parse(packet) as PacketParseResult.Parsed).metadata
        assertEquals(IpVersion.IPV6, metadata.ipVersion)
        assertEquals(PacketTransportProtocol.TCP, metadata.protocol)
        assertEquals(DestinationScope.PUBLIC, metadata.destinationScope)
    }

    @Test
    fun uniqueLocalIpv6IsNotPublic() {
        val destination = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 1 }
        val metadata = (PacketMetadataParser.parse(ipv6Packet(6, destination, 443)) as PacketParseResult.Parsed).metadata
        assertEquals(DestinationScope.LOCAL_PRIVATE, metadata.destinationScope)
    }

    @Test
    fun ipv6ExtensionHeaderFailsClosedForNow() {
        val destination = ByteArray(16).also { it[0] = 0x20; it[1] = 0x01; it[15] = 1 }
        val result = PacketMetadataParser.parse(ipv6Packet(0, destination, 443))
        assertEquals(PacketParseFailure.UNSUPPORTED_EXTENSION_HEADER, (result as PacketParseResult.Rejected).failure)
    }


    @Test
    fun tcpHeaderWithInvalidDataOffsetFailsClosed() {
        val packet = ipv4Packet(protocol = 6, destination = byteArrayOf(8, 8, 8, 8), destinationPort = 443)
        packet[32] = 0x40
        val result = PacketMetadataParser.parse(packet)
        assertEquals(PacketParseFailure.INVALID_TRANSPORT_HEADER, (result as PacketParseResult.Rejected).failure)
    }

    @Test
    fun udpLengthBeyondPacketFailsClosed() {
        val packet = ipv4Packet(protocol = 17, destination = byteArrayOf(8, 8, 8, 8), destinationPort = 53)
        packet[24] = 0x7f
        packet[25] = 0xff.toByte()
        val result = PacketMetadataParser.parse(packet)
        assertEquals(PacketParseFailure.INVALID_TRANSPORT_HEADER, (result as PacketParseResult.Rejected).failure)
    }

    @Test
    fun ipv4DeclaredTrailingAmbiguityFailsClosed() {
        val packet = ipv4Packet(protocol = 6, destination = byteArrayOf(8, 8, 8, 8), destinationPort = 443)
        packet[3] = 39
        val result = PacketMetadataParser.parse(packet)
        assertEquals(PacketParseFailure.INVALID_TOTAL_LENGTH, (result as PacketParseResult.Rejected).failure)
    }

    @Test
    fun ipv6LoopbackIsNotPublic() {
        val destination = ByteArray(16).also { it[15] = 1 }
        val metadata = (PacketMetadataParser.parse(ipv6Packet(6, destination, 443)) as PacketParseResult.Parsed).metadata
        assertEquals(DestinationScope.LOOPBACK, metadata.destinationScope)
    }

    @Test
    fun ipv6LinkLocalIsNotPublic() {
        val destination = ByteArray(16).also { it[0] = 0xfe.toByte(); it[1] = 0x80.toByte(); it[15] = 1 }
        val metadata = (PacketMetadataParser.parse(ipv6Packet(6, destination, 443)) as PacketParseResult.Parsed).metadata
        assertEquals(DestinationScope.LINK_LOCAL, metadata.destinationScope)
    }

    @Test
    fun ipv6MulticastIsNotPublic() {
        val destination = ByteArray(16).also { it[0] = 0xff.toByte(); it[1] = 0x02; it[15] = 1 }
        val metadata = (PacketMetadataParser.parse(ipv6Packet(17, destination, 53)) as PacketParseResult.Parsed).metadata
        assertEquals(DestinationScope.MULTICAST, metadata.destinationScope)
    }

    @Test
    fun ipv6DocumentationPrefixIsReserved() {
        val destination = byteArrayOf(
            0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        )
        val metadata = (PacketMetadataParser.parse(ipv6Packet(6, destination, 443)) as PacketParseResult.Parsed).metadata
        assertEquals(DestinationScope.RESERVED, metadata.destinationScope)
    }

    private fun ipv4Packet(protocol: Int, destination: ByteArray, destinationPort: Int): ByteArray {
        val packet = ByteArray(40)
        packet[0] = 0x45
        packet[2] = 0
        packet[3] = 40
        packet[8] = 64
        packet[9] = protocol.toByte()
        packet[12] = 10
        packet[13] = 0
        packet[14] = 0
        packet[15] = 2
        destination.copyInto(packet, destinationOffset = 16)
        packet[20] = 0x30
        packet[21] = 0x39
        packet[22] = (destinationPort ushr 8).toByte()
        packet[23] = destinationPort.toByte()
        if (protocol == 6) {
            packet[32] = 0x50
        } else if (protocol == 17) {
            packet[24] = 0
            packet[25] = 20
        }
        return packet
    }

    private fun ipv6Packet(nextHeader: Int, destination: ByteArray, destinationPort: Int): ByteArray {
        val packet = ByteArray(60)
        packet[0] = 0x60
        packet[4] = 0
        packet[5] = 20
        packet[6] = nextHeader.toByte()
        packet[7] = 64
        byteArrayOf(0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1).copyInto(packet, 8)
        destination.copyInto(packet, 24)
        packet[40] = 0x30
        packet[41] = 0x39
        packet[42] = (destinationPort ushr 8).toByte()
        packet[43] = destinationPort.toByte()
        if (nextHeader == 6) {
            packet[52] = 0x50
        } else if (nextHeader == 17) {
            packet[44] = 0
            packet[45] = 20
        }
        return packet
    }
}
