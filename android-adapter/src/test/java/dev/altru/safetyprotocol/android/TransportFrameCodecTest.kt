package dev.altru.safetyprotocol.android

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class TransportFrameCodecTest {
    @Test
    fun roundTripsBoundedFrame() {
        val frame = TransportFrame(
            type = TransportFrameType.DATA,
            sequence = 7,
            payload = byteArrayOf(1, 2, 3, 4),
        )
        val bytes = ByteArrayOutputStream().also { TransportFrameCodec.write(it, frame) }.toByteArray()
        val decoded = TransportFrameCodec.read(ByteArrayInputStream(bytes))
        assertEquals(frame.type, decoded.type)
        assertEquals(frame.sequence, decoded.sequence)
        assertArrayEquals(frame.payload, decoded.payload)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsOversizedPayloadAtConstruction() {
        TransportFrame(
            type = TransportFrameType.DATA,
            sequence = 1,
            payload = ByteArray(TransportFrameCodec.MAX_PAYLOAD_BYTES + 1),
        )
    }

    @Test(expected = TransportProtocolException::class)
    fun rejectsBadMagic() {
        val bytes = ByteArrayOutputStream().also {
            TransportFrameCodec.write(it, TransportFrame(TransportFrameType.PING, 1, byteArrayOf(9)))
        }.toByteArray()
        bytes[0] = 0
        TransportFrameCodec.read(ByteArrayInputStream(bytes))
    }

    @Test(expected = TransportProtocolException::class)
    fun rejectsUnsupportedVersion() {
        val bytes = ByteArrayOutputStream().also {
            TransportFrameCodec.write(it, TransportFrame(TransportFrameType.PING, 1, byteArrayOf(9)))
        }.toByteArray()
        bytes[4] = 99
        TransportFrameCodec.read(ByteArrayInputStream(bytes))
    }

    @Test(expected = TransportProtocolException::class)
    fun rejectsTruncatedPayload() {
        val bytes = ByteArrayOutputStream().also {
            TransportFrameCodec.write(it, TransportFrame(TransportFrameType.PING, 1, byteArrayOf(1, 2, 3)))
        }.toByteArray().copyOfRange(0, TransportFrameCodec.HEADER_BYTES + 1)
        TransportFrameCodec.read(ByteArrayInputStream(bytes))
    }

    @Test(expected = TransportProtocolException::class)
    fun rejectsOversizedDeclaredPayloadBeforeAllocation() {
        val bytes = ByteArrayOutputStream().also {
            TransportFrameCodec.write(it, TransportFrame(TransportFrameType.PING, 1, byteArrayOf(9)))
        }.toByteArray()
        val lengthOffset = TransportFrameCodec.HEADER_BYTES - 4
        val tooLarge = TransportFrameCodec.MAX_PAYLOAD_BYTES + 1
        bytes[lengthOffset] = (tooLarge ushr 24).toByte()
        bytes[lengthOffset + 1] = (tooLarge ushr 16).toByte()
        bytes[lengthOffset + 2] = (tooLarge ushr 8).toByte()
        bytes[lengthOffset + 3] = tooLarge.toByte()
        TransportFrameCodec.read(ByteArrayInputStream(bytes))
    }

}
