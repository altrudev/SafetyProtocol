package dev.altru.safetyprotocol.android

enum class IpVersion {
    IPV4,
    IPV6,
}

enum class PacketTransportProtocol {
    TCP,
    UDP,
    OTHER,
}

enum class DestinationScope {
    PUBLIC,
    LOCAL_PRIVATE,
    LINK_LOCAL,
    LOOPBACK,
    MULTICAST,
    UNSPECIFIED,
    BROADCAST,
    RESERVED,
}

data class PacketMetadata(
    val ipVersion: IpVersion,
    val protocol: PacketTransportProtocol,
    val destinationScope: DestinationScope,
    val destinationPort: Int?,
    val packetLength: Int,
)

enum class PacketParseFailure {
    EMPTY_PACKET,
    PACKET_TOO_LARGE,
    UNSUPPORTED_IP_VERSION,
    TRUNCATED_PACKET,
    INVALID_HEADER_LENGTH,
    INVALID_TOTAL_LENGTH,
    FRAGMENTED_PACKET,
    UNSUPPORTED_EXTENSION_HEADER,
    UNSUPPORTED_JUMBOGRAM,
    INVALID_DESTINATION_PORT,
    INVALID_TRANSPORT_HEADER,
}

sealed interface PacketParseResult {
    data class Parsed(val metadata: PacketMetadata) : PacketParseResult
    data class Rejected(val failure: PacketParseFailure) : PacketParseResult
}

object PacketMetadataParser {
    fun parse(packet: ByteArray): PacketParseResult {
        if (packet.isEmpty()) return PacketParseResult.Rejected(PacketParseFailure.EMPTY_PACKET)
        if (packet.size > MAX_PACKET_BYTES) {
            return PacketParseResult.Rejected(PacketParseFailure.PACKET_TOO_LARGE)
        }
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> parseIpv4(packet)
            6 -> parseIpv6(packet)
            else -> PacketParseResult.Rejected(PacketParseFailure.UNSUPPORTED_IP_VERSION)
        }
    }

    private fun parseIpv4(packet: ByteArray): PacketParseResult {
        if (packet.size < IPV4_MIN_HEADER) {
            return PacketParseResult.Rejected(PacketParseFailure.TRUNCATED_PACKET)
        }

        val ihlBytes = (packet[0].u8() and 0x0f) * 4
        if (ihlBytes < IPV4_MIN_HEADER || ihlBytes > packet.size) {
            return PacketParseResult.Rejected(PacketParseFailure.INVALID_HEADER_LENGTH)
        }

        val totalLength = u16(packet, 2)
        if (totalLength < ihlBytes || totalLength > packet.size) {
            return PacketParseResult.Rejected(PacketParseFailure.TRUNCATED_PACKET)
        }
        if (totalLength != packet.size) {
            return PacketParseResult.Rejected(PacketParseFailure.INVALID_TOTAL_LENGTH)
        }

        val fragmentField = u16(packet, 6)
        val moreFragments = fragmentField and 0x2000 != 0
        val fragmentOffset = fragmentField and 0x1fff
        if (moreFragments || fragmentOffset != 0) {
            return PacketParseResult.Rejected(PacketParseFailure.FRAGMENTED_PACKET)
        }

        val protocol = transportProtocol(packet[9].u8())
        val destinationPort = when (protocol) {
            PacketTransportProtocol.TCP -> parseTcpDestinationPort(packet, ihlBytes, totalLength)
                ?: return PacketParseResult.Rejected(PacketParseFailure.INVALID_TRANSPORT_HEADER)
            PacketTransportProtocol.UDP -> parseUdpDestinationPort(packet, ihlBytes, totalLength)
                ?: return PacketParseResult.Rejected(PacketParseFailure.INVALID_TRANSPORT_HEADER)
            PacketTransportProtocol.OTHER -> null
        }

        if (destinationPort == 0) {
            return PacketParseResult.Rejected(PacketParseFailure.INVALID_DESTINATION_PORT)
        }

        val destination = packet.copyOfRange(16, 20)
        return PacketParseResult.Parsed(
            PacketMetadata(
                ipVersion = IpVersion.IPV4,
                protocol = protocol,
                destinationScope = classifyIpv4(destination),
                destinationPort = destinationPort,
                packetLength = totalLength,
            ),
        )
    }

    private fun parseIpv6(packet: ByteArray): PacketParseResult {
        if (packet.size < IPV6_HEADER) {
            return PacketParseResult.Rejected(PacketParseFailure.TRUNCATED_PACKET)
        }

        val payloadLength = u16(packet, 4)
        if (payloadLength == 0) {
            return PacketParseResult.Rejected(PacketParseFailure.UNSUPPORTED_JUMBOGRAM)
        }

        val totalLength = IPV6_HEADER + payloadLength
        if (totalLength > packet.size) {
            return PacketParseResult.Rejected(PacketParseFailure.TRUNCATED_PACKET)
        }
        if (totalLength != packet.size) {
            return PacketParseResult.Rejected(PacketParseFailure.INVALID_TOTAL_LENGTH)
        }

        val nextHeader = packet[6].u8()
        if (nextHeader in IPV6_EXTENSION_HEADERS) {
            return PacketParseResult.Rejected(PacketParseFailure.UNSUPPORTED_EXTENSION_HEADER)
        }

        val protocol = transportProtocol(nextHeader)
        val destinationPort = when (protocol) {
            PacketTransportProtocol.TCP -> parseTcpDestinationPort(packet, IPV6_HEADER, totalLength)
                ?: return PacketParseResult.Rejected(PacketParseFailure.INVALID_TRANSPORT_HEADER)
            PacketTransportProtocol.UDP -> parseUdpDestinationPort(packet, IPV6_HEADER, totalLength)
                ?: return PacketParseResult.Rejected(PacketParseFailure.INVALID_TRANSPORT_HEADER)
            PacketTransportProtocol.OTHER -> null
        }

        if (destinationPort == 0) {
            return PacketParseResult.Rejected(PacketParseFailure.INVALID_DESTINATION_PORT)
        }

        val destination = packet.copyOfRange(24, 40)
        return PacketParseResult.Parsed(
            PacketMetadata(
                ipVersion = IpVersion.IPV6,
                protocol = protocol,
                destinationScope = classifyIpv6(destination),
                destinationPort = destinationPort,
                packetLength = totalLength,
            ),
        )
    }

    private fun parseTcpDestinationPort(
        packet: ByteArray,
        offset: Int,
        totalLength: Int,
    ): Int? {
        if (offset + TCP_MIN_HEADER > totalLength || offset + TCP_MIN_HEADER > packet.size) return null
        val dataOffsetBytes = ((packet[offset + 12].u8() ushr 4) and 0x0f) * 4
        if (dataOffsetBytes < TCP_MIN_HEADER || offset + dataOffsetBytes > totalLength) return null
        return u16(packet, offset + 2)
    }

    private fun parseUdpDestinationPort(
        packet: ByteArray,
        offset: Int,
        totalLength: Int,
    ): Int? {
        if (offset + UDP_HEADER > totalLength || offset + UDP_HEADER > packet.size) return null
        val udpLength = u16(packet, offset + 4)
        if (udpLength < UDP_HEADER || offset + udpLength > totalLength) return null
        return u16(packet, offset + 2)
    }

    private fun transportProtocol(number: Int): PacketTransportProtocol = when (number) {
        6 -> PacketTransportProtocol.TCP
        17 -> PacketTransportProtocol.UDP
        else -> PacketTransportProtocol.OTHER
    }

    private fun classifyIpv4(address: ByteArray): DestinationScope {
        val a = address[0].u8()
        val b = address[1].u8()
        val c = address[2].u8()
        val d = address[3].u8()

        if (a == 0 && b == 0 && c == 0 && d == 0) return DestinationScope.UNSPECIFIED
        if (a == 255 && b == 255 && c == 255 && d == 255) return DestinationScope.BROADCAST
        if (a == 127) return DestinationScope.LOOPBACK
        if (a == 169 && b == 254) return DestinationScope.LINK_LOCAL
        if (a in 224..239) return DestinationScope.MULTICAST

        if (a == 10 ||
            (a == 172 && b in 16..31) ||
            (a == 192 && b == 168) ||
            (a == 100 && b in 64..127)
        ) {
            return DestinationScope.LOCAL_PRIVATE
        }

        if (a == 0 ||
            a >= 240 ||
            (a == 192 && b == 0 && c == 0) ||
            (a == 192 && b == 0 && c == 2) ||
            (a == 198 && b in 18..19) ||
            (a == 198 && b == 51 && c == 100) ||
            (a == 203 && b == 0 && c == 113)
        ) {
            return DestinationScope.RESERVED
        }

        return DestinationScope.PUBLIC
    }

    private fun classifyIpv6(address: ByteArray): DestinationScope {
        if (address.all { it == 0.toByte() }) return DestinationScope.UNSPECIFIED
        if (address.dropLast(1).all { it == 0.toByte() } && address.last() == 1.toByte()) {
            return DestinationScope.LOOPBACK
        }

        val first = address[0].u8()
        val second = address[1].u8()

        if (first == 0xff) return DestinationScope.MULTICAST
        if (first == 0xfe && second and 0xc0 == 0x80) return DestinationScope.LINK_LOCAL
        if (first and 0xfe == 0xfc) return DestinationScope.LOCAL_PRIVATE
        if (first == 0xfe && second and 0xc0 == 0xc0) return DestinationScope.RESERVED

        if (isIpv4Mapped(address) ||
            isDocumentationIpv6(address)
        ) {
            return DestinationScope.RESERVED
        }

        return DestinationScope.PUBLIC
    }

    private fun isIpv4Mapped(address: ByteArray): Boolean =
        address.sliceArray(0 until 10).all { it == 0.toByte() } &&
            address[10] == 0xff.toByte() &&
            address[11] == 0xff.toByte()

    private fun isDocumentationIpv6(address: ByteArray): Boolean =
        address[0].u8() == 0x20 &&
            address[1].u8() == 0x01 &&
            address[2].u8() == 0x0d &&
            address[3].u8() == 0xb8

    private fun Byte.u8(): Int = toInt() and 0xff

    private fun u16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].u8() shl 8) or bytes[offset + 1].u8()

    const val MAX_PACKET_BYTES = 65_535

    private const val IPV4_MIN_HEADER = 20
    private const val IPV6_HEADER = 40
    private const val TCP_MIN_HEADER = 20
    private const val UDP_HEADER = 8

    private val IPV6_EXTENSION_HEADERS = setOf(
        0,   // Hop-by-Hop Options
        43,  // Routing
        44,  // Fragment
        50,  // ESP
        51,  // AH
        60,  // Destination Options
        135, // Mobility
        139, // HIP
        140, // Shim6
        253,
        254,
    )
}
