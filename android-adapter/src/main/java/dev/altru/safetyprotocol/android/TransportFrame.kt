package dev.altru.safetyprotocol.android

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

enum class TransportFrameType(val code: Int) {
    PING(1),
    PONG(2),
    DATA(3),
    CLOSE(4);

    companion object {
        fun fromCode(code: Int): TransportFrameType = entries.firstOrNull { it.code == code }
            ?: throw TransportProtocolException("Unknown frame type: $code")
    }
}

class TransportProtocolException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class TransportFrame(
    val type: TransportFrameType,
    val sequence: Long,
    val payload: ByteArray = ByteArray(0),
) {
    init {
        require(sequence >= 0) { "Frame sequence must be non-negative" }
        require(payload.size <= TransportFrameCodec.MAX_PAYLOAD_BYTES) {
            "Frame payload exceeds ${TransportFrameCodec.MAX_PAYLOAD_BYTES} bytes"
        }
    }
}

object TransportFrameCodec {
    const val VERSION = 1
    const val MAX_PAYLOAD_BYTES = 64 * 1024
    const val HEADER_BYTES = 20

    private const val MAGIC = 0x53504631 // SPF1
    private const val FLAGS_NONE = 0

    fun write(output: OutputStream, frame: TransportFrame) {
        val data = DataOutputStream(output)
        data.writeInt(MAGIC)
        data.writeByte(VERSION)
        data.writeByte(frame.type.code)
        data.writeShort(FLAGS_NONE)
        data.writeLong(frame.sequence)
        data.writeInt(frame.payload.size)
        data.write(frame.payload)
        data.flush()
    }

    @Throws(TransportProtocolException::class)
    fun read(input: InputStream): TransportFrame {
        val data = DataInputStream(input)
        try {
            val magic = data.readInt()
            if (magic != MAGIC) throw TransportProtocolException("Invalid frame magic")

            val version = data.readUnsignedByte()
            if (version != VERSION) throw TransportProtocolException("Unsupported frame version: $version")

            val type = TransportFrameType.fromCode(data.readUnsignedByte())
            val flags = data.readUnsignedShort()
            if (flags != FLAGS_NONE) throw TransportProtocolException("Unsupported frame flags: $flags")

            val sequence = data.readLong()
            if (sequence < 0) throw TransportProtocolException("Negative frame sequence")

            val payloadLength = data.readInt()
            if (payloadLength < 0 || payloadLength > MAX_PAYLOAD_BYTES) {
                throw TransportProtocolException("Invalid frame payload length: $payloadLength")
            }

            val payload = ByteArray(payloadLength)
            data.readFully(payload)
            return TransportFrame(type, sequence, payload)
        } catch (e: TransportProtocolException) {
            throw e
        } catch (e: EOFException) {
            throw TransportProtocolException("Truncated transport frame", e)
        }
    }
}

class FramedTransportChannel(
    input: InputStream,
    output: OutputStream,
) {
    private val inputStream = input
    private val outputStream = output
    private val writeLock = Any()

    fun read(): TransportFrame = TransportFrameCodec.read(inputStream)

    fun write(frame: TransportFrame) {
        synchronized(writeLock) {
            TransportFrameCodec.write(outputStream, frame)
        }
    }
}
