package dev.altru.safetyprotocol.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DestinationPolicyTest {
    @Test
    fun emptyPolicyFailsClosed() {
        val policy = DestinationPolicy(emptyList())
        val result = policy.evaluate(ipv4(8, 8, 8, 8))
        assertEquals(DestinationPolicyDisposition.DENY, result.disposition)
        assertEquals(DestinationPolicyReason.NO_MATCHING_ALLOW_RULE, result.reason)
    }

    @Test
    fun explicitAllowCidrPermitsMatchingPublicAddress() {
        val policy = DestinationPolicy(
            listOf(DestinationRule.allow("8.8.8.0/24")),
        )
        val result = policy.evaluate(ipv4(8, 8, 8, 8))
        assertEquals(DestinationPolicyDisposition.ALLOW, result.disposition)
    }

    @Test
    fun moreSpecificDenyOverridesBroaderAllow() {
        val policy = DestinationPolicy(
            listOf(
                DestinationRule.allow("8.0.0.0/8"),
                DestinationRule.deny("8.8.8.0/24"),
            ),
        )
        val result = policy.evaluate(ipv4(8, 8, 8, 8))
        assertEquals(DestinationPolicyDisposition.DENY, result.disposition)
        assertEquals(DestinationPolicyReason.EXPLICIT_DENY, result.reason)
    }

    @Test
    fun samePrefixDenyWins() {
        val policy = DestinationPolicy(
            listOf(
                DestinationRule.allow("8.8.8.0/24"),
                DestinationRule.deny("8.8.8.0/24"),
            ),
        )
        assertEquals(DestinationPolicyDisposition.DENY, policy.evaluate(ipv4(8, 8, 8, 8)).disposition)
    }

    @Test
    fun ruleForWrongAddressFamilyDoesNotMatch() {
        val policy = DestinationPolicy(listOf(DestinationRule.allow("2001:4860:4860::/48")))
        assertEquals(DestinationPolicyDisposition.DENY, policy.evaluate(ipv4(8, 8, 8, 8)).disposition)
    }

    @Test
    fun ipv6PrefixMatchesExactly() {
        val policy = DestinationPolicy(listOf(DestinationRule.allow("2001:4860:4860::/48")))
        val result = policy.evaluate(ipv6("2001:4860:4860::8888"))
        assertEquals(DestinationPolicyDisposition.ALLOW, result.disposition)
    }

    @Test(expected = IllegalArgumentException::class)
    fun malformedCidrIsRejectedAtConstruction() {
        DestinationRule.allow("8.8.8.0/99")
    }

    @Test
    fun policyNeverOverridesNonPublicScope() {
        val policy = DestinationPolicy(listOf(DestinationRule.allow("0.0.0.0/0")))
        val result = policy.evaluate(
            PacketDestination(IpVersion.IPV4, byteArrayOf(10, 0, 0, 1), DestinationScope.LOCAL_PRIVATE),
        )
        assertEquals(DestinationPolicyDisposition.DENY, result.disposition)
        assertEquals(DestinationPolicyReason.NON_PUBLIC_SCOPE, result.reason)
    }


    @Test
    fun zeroPrefixAllowsAnyPublicIpv4WhenExplicitlyConfigured() {
        val policy = DestinationPolicy(listOf(DestinationRule.allow("0.0.0.0/0")))
        assertEquals(DestinationPolicyDisposition.ALLOW, policy.evaluate(ipv4(8, 8, 4, 4)).disposition)
    }

    @Test
    fun exactIpv4HostRuleMatchesOnlyHost() {
        val policy = DestinationPolicy(listOf(DestinationRule.allow("8.8.8.8/32")))
        assertEquals(DestinationPolicyDisposition.ALLOW, policy.evaluate(ipv4(8, 8, 8, 8)).disposition)
        assertEquals(DestinationPolicyDisposition.DENY, policy.evaluate(ipv4(8, 8, 8, 9)).disposition)
    }

    @Test
    fun nonCanonicalNetworkLiteralIsMaskedToPrefix() {
        val policy = DestinationPolicy(listOf(DestinationRule.allow("8.8.8.200/24")))
        assertEquals(DestinationPolicyDisposition.ALLOW, policy.evaluate(ipv4(8, 8, 8, 1)).disposition)
    }

    @Test
    fun exactIpv6HostRuleMatchesOnlyHost() {
        val policy = DestinationPolicy(listOf(DestinationRule.allow("2001:4860:4860::8888/128")))
        assertEquals(DestinationPolicyDisposition.ALLOW, policy.evaluate(ipv6("2001:4860:4860::8888")).disposition)
        assertEquals(DestinationPolicyDisposition.DENY, policy.evaluate(ipv6("2001:4860:4860::8844")).disposition)
    }

    @Test(expected = IllegalArgumentException::class)
    fun hostnamesAreRejectedInsteadOfResolved() {
        DestinationRule.allow("example.com/24")
    }

    @Test(expected = IllegalArgumentException::class)
    fun cidrWithoutPrefixIsRejected() {
        DestinationRule.allow("8.8.8.8")
    }

    private fun ipv4(a: Int, b: Int, c: Int, d: Int) =
        PacketDestination(IpVersion.IPV4, byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte()), DestinationScope.PUBLIC)

    private fun ipv6(text: String) =
        PacketDestination.fromLiteral(text, DestinationScope.PUBLIC)
}
