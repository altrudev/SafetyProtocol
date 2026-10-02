package dev.altru.safetyprotocol.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class ProtectedTransportEndpointTest {
    @Test
    fun parsesExactSha256HexPin() {
        val pin = "00".repeat(31) + "ff"
        val endpoint = ProtectedTransportEndpoint.fromHexPin("example.com", 443, pin)
        assertEquals("example.com", endpoint.host)
        assertEquals(443, endpoint.port)
        assertArrayEquals(ByteArray(32).also { it[31] = 0xff.toByte() }, endpoint.spkiSha256)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsShortPin() {
        ProtectedTransportEndpoint.fromHexPin("example.com", 443, "00")
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsInvalidPort() {
        ProtectedTransportEndpoint("example.com", 0, ByteArray(32))
    }
}
