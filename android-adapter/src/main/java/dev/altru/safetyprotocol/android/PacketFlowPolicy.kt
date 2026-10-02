package dev.altru.safetyprotocol.android

enum class PacketFlowDisposition {
    DENY,
    ALLOW_TO_FORWARDING_GATE,
}

enum class PacketFlowReason {
    PUBLIC_DESTINATION,
    PUBLIC_DNS_OVER_PROTECTED_TRANSPORT,
    LOCAL_DESTINATION_NOT_AUTHORIZED,
    NON_PUBLIC_DESTINATION_NOT_AUTHORIZED,
    UNSUPPORTED_TRANSPORT_PROTOCOL,
    INVALID_DESTINATION_PORT,
}

data class PacketFlowDecision(
    val disposition: PacketFlowDisposition,
    val reason: PacketFlowReason,
)

object PacketFlowPolicy {
    fun evaluate(metadata: PacketMetadata): PacketFlowDecision {
        if (metadata.protocol != PacketTransportProtocol.TCP &&
            metadata.protocol != PacketTransportProtocol.UDP
        ) {
            return deny(PacketFlowReason.UNSUPPORTED_TRANSPORT_PROTOCOL)
        }

        val port = metadata.destinationPort
            ?: return deny(PacketFlowReason.INVALID_DESTINATION_PORT)
        if (port !in 1..65535) {
            return deny(PacketFlowReason.INVALID_DESTINATION_PORT)
        }

        when (metadata.destinationScope) {
            DestinationScope.LOCAL_PRIVATE,
            DestinationScope.LINK_LOCAL,
            DestinationScope.LOOPBACK,
            -> return deny(PacketFlowReason.LOCAL_DESTINATION_NOT_AUTHORIZED)

            DestinationScope.MULTICAST,
            DestinationScope.UNSPECIFIED,
            DestinationScope.BROADCAST,
            DestinationScope.RESERVED,
            -> return deny(PacketFlowReason.NON_PUBLIC_DESTINATION_NOT_AUTHORIZED)

            DestinationScope.PUBLIC -> Unit
        }

        return if (port == 53) {
            PacketFlowDecision(
                PacketFlowDisposition.ALLOW_TO_FORWARDING_GATE,
                PacketFlowReason.PUBLIC_DNS_OVER_PROTECTED_TRANSPORT,
            )
        } else {
            PacketFlowDecision(
                PacketFlowDisposition.ALLOW_TO_FORWARDING_GATE,
                PacketFlowReason.PUBLIC_DESTINATION,
            )
        }
    }

    private fun deny(reason: PacketFlowReason) =
        PacketFlowDecision(PacketFlowDisposition.DENY, reason)
}
