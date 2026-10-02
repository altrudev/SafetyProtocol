package dev.altru.safetyprotocol.android

import java.net.InetAddress

enum class DestinationRuleAction {
    ALLOW,
    DENY,
}

class PacketDestination internal constructor(
    val ipVersion: IpVersion,
    internal val addressBytes: ByteArray,
    val scope: DestinationScope,
) {
    init {
        require(
            (ipVersion == IpVersion.IPV4 && addressBytes.size == IPV4_BYTES) ||
                (ipVersion == IpVersion.IPV6 && addressBytes.size == IPV6_BYTES),
        )
    }

    companion object {
        private const val IPV4_BYTES = 4
        private const val IPV6_BYTES = 16

        internal fun fromBytes(
            ipVersion: IpVersion,
            bytes: ByteArray,
            scope: DestinationScope,
        ) = PacketDestination(ipVersion, bytes.copyOf(), scope)

        internal fun fromLiteral(
            literal: String,
            scope: DestinationScope,
        ): PacketDestination {
            val bytes = parseLiteralAddress(literal)
            val version = when (bytes.size) {
                IPV4_BYTES -> IpVersion.IPV4
                IPV6_BYTES -> IpVersion.IPV6
                else -> throw IllegalArgumentException("Unsupported IP address size")
            }
            return PacketDestination(version, bytes, scope)
        }

        internal fun parseLiteralAddress(literal: String): ByteArray {
            require(literal.isNotBlank()) { "IP literal must not be blank" }
            require(literal.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == '.' || it == ':' }) {
                "Only numeric IPv4/IPv6 literals are allowed"
            }

            if ('.' in literal && ':' !in literal) {
                val parts = literal.split('.')
                require(parts.size == 4) { "Invalid IPv4 literal" }
                return ByteArray(4) { index ->
                    val part = parts[index]
                    require(part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit)) {
                        "Invalid IPv4 octet"
                    }
                    val value = part.toInt()
                    require(value in 0..255) { "Invalid IPv4 octet" }
                    value.toByte()
                }
            }

            require(':' in literal) { "Invalid IP literal" }
            val parsed = InetAddress.getByName(literal).address
            require(parsed.size == IPV6_BYTES) { "Expected IPv6 literal" }
            return parsed
        }
    }
}

class DestinationRule private constructor(
    val action: DestinationRuleAction,
    val ipVersion: IpVersion,
    private val networkBytes: ByteArray,
    val prefixLength: Int,
) {
    companion object {
        fun allow(cidr: String): DestinationRule = parse(DestinationRuleAction.ALLOW, cidr)
        fun deny(cidr: String): DestinationRule = parse(DestinationRuleAction.DENY, cidr)

        private fun parse(action: DestinationRuleAction, cidr: String): DestinationRule {
            val slash = cidr.lastIndexOf('/')
            require(slash > 0 && slash < cidr.length - 1) { "CIDR prefix length required" }

            val literal = cidr.substring(0, slash)
            val address = PacketDestination.parseLiteralAddress(literal)
            val maxBits = address.size * 8
            val prefix = cidr.substring(slash + 1).toIntOrNull()
                ?: throw IllegalArgumentException("Invalid CIDR prefix length")
            require(prefix in 0..maxBits) { "CIDR prefix out of range" }

            val version = if (address.size == 4) IpVersion.IPV4 else IpVersion.IPV6
            return DestinationRule(
                action = action,
                ipVersion = version,
                networkBytes = maskAddress(address, prefix),
                prefixLength = prefix,
            )
        }

        private fun maskAddress(address: ByteArray, prefixLength: Int): ByteArray {
            val out = address.copyOf()
            var remaining = prefixLength
            for (i in out.indices) {
                when {
                    remaining >= 8 -> remaining -= 8
                    remaining <= 0 -> out[i] = 0
                    else -> {
                        val mask = (0xff shl (8 - remaining)) and 0xff
                        out[i] = ((out[i].toInt() and 0xff) and mask).toByte()
                        remaining = 0
                    }
                }
            }
            return out
        }
    }

    internal fun matches(destination: PacketDestination): Boolean {
        if (destination.ipVersion != ipVersion) return false
        var remaining = prefixLength
        for (i in networkBytes.indices) {
            if (remaining <= 0) return true
            val bits = minOf(remaining, 8)
            val mask = (0xff shl (8 - bits)) and 0xff
            val expected = networkBytes[i].toInt() and 0xff and mask
            val actual = destination.addressBytes[i].toInt() and 0xff and mask
            if (expected != actual) return false
            remaining -= bits
        }
        return true
    }
}

enum class DestinationPolicyDisposition {
    ALLOW,
    DENY,
}

enum class DestinationPolicyReason {
    MATCHED_ALLOW,
    EXPLICIT_DENY,
    NO_MATCHING_ALLOW_RULE,
    NON_PUBLIC_SCOPE,
}

data class DestinationPolicyDecision(
    val disposition: DestinationPolicyDisposition,
    val reason: DestinationPolicyReason,
    val matchedPrefixLength: Int? = null,
)

class DestinationPolicy(
    rules: List<DestinationRule>,
) {
    private val rules = rules.toList()

    fun evaluate(destination: PacketDestination): DestinationPolicyDecision {
        if (destination.scope != DestinationScope.PUBLIC) {
            return deny(DestinationPolicyReason.NON_PUBLIC_SCOPE)
        }

        val matches = rules.filter { it.matches(destination) }
        if (matches.isEmpty()) {
            return deny(DestinationPolicyReason.NO_MATCHING_ALLOW_RULE)
        }

        val bestPrefix = matches.maxOf { it.prefixLength }
        val strongest = matches.filter { it.prefixLength == bestPrefix }
        val denyWins = strongest.any { it.action == DestinationRuleAction.DENY }

        return if (denyWins) {
            DestinationPolicyDecision(
                DestinationPolicyDisposition.DENY,
                DestinationPolicyReason.EXPLICIT_DENY,
                bestPrefix,
            )
        } else {
            DestinationPolicyDecision(
                DestinationPolicyDisposition.ALLOW,
                DestinationPolicyReason.MATCHED_ALLOW,
                bestPrefix,
            )
        }
    }

    private fun deny(reason: DestinationPolicyReason) =
        DestinationPolicyDecision(DestinationPolicyDisposition.DENY, reason)
}
