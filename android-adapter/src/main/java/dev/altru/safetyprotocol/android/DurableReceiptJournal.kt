package dev.altru.safetyprotocol.android

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

internal class ReceiptJournalIntegrityException(message: String) : IllegalStateException(message)
internal class ReceiptJournalCapacityException(message: String) : IllegalStateException(message)

internal data class ReceiptJournalVerification(
    val valid: Boolean,
    val recordCount: Long,
    val lastHash: ByteArray,
    val failure: String? = null,
)

internal class HashChainedReceiptJournal(
    private val file: File,
    private val anchorFile: File = File(file.parentFile ?: File("."), file.name + ".anchor"),
    private val maxRecords: Long = MAX_RECORDS,
    private val maxJournalBytes: Long = MAX_JOURNAL_BYTES,
) : ForwardingReceiptStore {
    companion object {
        private val MAGIC = byteArrayOf(
            'F'.code.toByte(), 'S'.code.toByte(), 'P'.code.toByte(), 'R'.code.toByte(),
            1, 2, 0, 1,
        )
        private val ANCHOR_MAGIC = byteArrayOf(
            'F'.code.toByte(), 'S'.code.toByte(), 'P'.code.toByte(), 'A'.code.toByte(),
            1, 2, 0, 1,
        )
        private const val HASH_BYTES = 32
        private const val MAX_RECORD_BYTES = 4_096
        const val MAX_RECORDS = 4_096L
        const val MAX_JOURNAL_BYTES = 1_048_576L
        private val ZERO_HASH = ByteArray(HASH_BYTES)
    }

    init {
        require(maxRecords in 1..MAX_RECORDS)
        require(maxJournalBytes in MAGIC.size.toLong()..MAX_JOURNAL_BYTES)
        file.parentFile?.mkdirs()
        val newJournal = !file.exists() || file.length() == 0L
        if (newJournal) {
            RandomAccessFile(file, "rw").use { raf ->
                raf.setLength(0)
                raf.write(MAGIC)
                raf.fd.sync()
            }
            writeAnchor(0L, ZERO_HASH)
        }
    }

    @Synchronized
    override fun append(receipt: ForwardingExecutionReceipt) {
        val verification = verify()
        if (!verification.valid) {
            throw ReceiptJournalIntegrityException(
                "Refusing append to invalid receipt journal: ${verification.failure ?: "unknown integrity failure"}",
            )
        }
        if (verification.recordCount >= maxRecords) {
            throw ReceiptJournalCapacityException("Receipt journal record ceiling reached")
        }

        val payload = encode(receipt, verification.lastHash)
        require(payload.size <= MAX_RECORD_BYTES) { "Receipt record exceeds bounded journal size" }
        val projectedBytes = Math.addExact(
            file.length(),
            Int.SIZE_BYTES.toLong() + payload.size.toLong() + HASH_BYTES.toLong(),
        )
        if (projectedBytes > maxJournalBytes) {
            throw ReceiptJournalCapacityException("Receipt journal byte ceiling reached")
        }
        val hash = sha256(payload)

        RandomAccessFile(file, "rw").use { raf ->
            raf.seek(raf.length())
            raf.writeInt(payload.size)
            raf.write(payload)
            raf.write(hash)
            raf.fd.sync()
        }

        writeAnchor(Math.addExact(verification.recordCount, 1L), hash)
    }

    @Synchronized
    fun verify(): ReceiptJournalVerification {
        if (!file.exists()) {
            return ReceiptJournalVerification(false, 0, ZERO_HASH.copyOf(), "journal missing")
        }

        return try {
            RandomAccessFile(file, "r").use { raf ->
                if (raf.length() < MAGIC.size) {
                    return ReceiptJournalVerification(false, 0, ZERO_HASH.copyOf(), "truncated header")
                }

                val magic = ByteArray(MAGIC.size)
                raf.readFully(magic)
                if (!magic.contentEquals(MAGIC)) {
                    return ReceiptJournalVerification(false, 0, ZERO_HASH.copyOf(), "invalid header")
                }

                var previousHash = ZERO_HASH.copyOf()
                var count = 0L

                while (raf.filePointer < raf.length()) {
                    if (count >= maxRecords) {
                        return ReceiptJournalVerification(false, count, previousHash.copyOf(), "record ceiling exceeded")
                    }
                    if (raf.length() > maxJournalBytes) {
                        return ReceiptJournalVerification(false, count, previousHash.copyOf(), "journal byte ceiling exceeded")
                    }

                    val remainingBeforeLength = raf.length() - raf.filePointer
                    if (remainingBeforeLength < Int.SIZE_BYTES) {
                        return ReceiptJournalVerification(false, count, previousHash.copyOf(), "truncated record length")
                    }

                    val size = raf.readInt()
                    if (size <= 0 || size > MAX_RECORD_BYTES) {
                        return ReceiptJournalVerification(false, count, previousHash.copyOf(), "invalid record size")
                    }

                    val required = size.toLong() + HASH_BYTES
                    if (raf.length() - raf.filePointer < required) {
                        return ReceiptJournalVerification(false, count, previousHash.copyOf(), "truncated record")
                    }

                    val payload = ByteArray(size)
                    raf.readFully(payload)
                    val storedHash = ByteArray(HASH_BYTES)
                    raf.readFully(storedHash)

                    val decodedPrevious = decodePreviousHash(payload)
                    if (!decodedPrevious.contentEquals(previousHash)) {
                        return ReceiptJournalVerification(false, count, previousHash.copyOf(), "hash-chain predecessor mismatch")
                    }

                    val computedHash = sha256(payload)
                    if (!storedHash.contentEquals(computedHash)) {
                        return ReceiptJournalVerification(false, count, previousHash.copyOf(), "record hash mismatch")
                    }

                    validatePayload(payload)
                    previousHash = storedHash
                    count = Math.addExact(count, 1L)
                }

                val anchorFailure = verifyAnchor(count, previousHash)
                if (anchorFailure != null) {
                    ReceiptJournalVerification(false, count, previousHash.copyOf(), anchorFailure)
                } else {
                    ReceiptJournalVerification(true, count, previousHash.copyOf())
                }
            }
        } catch (_: EOFException) {
            ReceiptJournalVerification(false, 0, ZERO_HASH.copyOf(), "unexpected end of journal")
        } catch (e: Exception) {
            ReceiptJournalVerification(false, 0, ZERO_HASH.copyOf(), e.message ?: e.javaClass.simpleName)
        }
    }

    private fun encode(
        receipt: ForwardingExecutionReceipt,
        previousHash: ByteArray,
    ): ByteArray {
        require(previousHash.size == HASH_BYTES)
        return ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { out ->
                out.write(previousHash)
                out.writeInt(1)
                out.writeLong(receipt.permitId)
                out.writeLong(receipt.revision.contextRevision)
                out.writeLong(receipt.revision.runtimeRevision)
                out.writeLong(receipt.frameSequence)
                out.writeInt(receipt.frameLength)
                out.writeUTF(receipt.disposition.name)
                out.writeUTF(receipt.reason.name)
                out.writeLong(receipt.issuedAtMs)
                out.writeLong(receipt.terminalAtMs)
                out.flush()
            }
            bytes.toByteArray()
        }
    }

    private fun decodePreviousHash(payload: ByteArray): ByteArray {
        if (payload.size < HASH_BYTES) {
            throw ReceiptJournalIntegrityException("record too small for predecessor hash")
        }
        return payload.copyOfRange(0, HASH_BYTES)
    }

    private fun validatePayload(payload: ByteArray) {
        DataInputStream(ByteArrayInputStream(payload)).use { input ->
            val previous = ByteArray(HASH_BYTES)
            input.readFully(previous)
            val version = input.readInt()
            if (version != 1) throw ReceiptJournalIntegrityException("unsupported receipt record version")
            input.readLong()
            input.readLong()
            input.readLong()
            input.readLong()
            val frameLength = input.readInt()
            if (frameLength < 0) throw ReceiptJournalIntegrityException("negative frame length")
            ForwardingReceiptDisposition.valueOf(input.readUTF())
            ForwardingExecutionReason.valueOf(input.readUTF())
            val issuedAt = input.readLong()
            val terminalAt = input.readLong()
            if (terminalAt < issuedAt) throw ReceiptJournalIntegrityException("terminal time precedes issue time")
            if (input.available() != 0) throw ReceiptJournalIntegrityException("unexpected trailing receipt bytes")
        }
    }

    private fun verifyAnchor(expectedCount: Long, expectedHash: ByteArray): String? {
        if (!anchorFile.exists()) return "receipt anchor missing"
        return try {
            RandomAccessFile(anchorFile, "r").use { raf ->
                val expectedLength = ANCHOR_MAGIC.size + Long.SIZE_BYTES + HASH_BYTES
                if (raf.length() != expectedLength.toLong()) return "invalid receipt anchor length"
                val magic = ByteArray(ANCHOR_MAGIC.size)
                raf.readFully(magic)
                if (!magic.contentEquals(ANCHOR_MAGIC)) return "invalid receipt anchor header"
                val count = raf.readLong()
                val hash = ByteArray(HASH_BYTES)
                raf.readFully(hash)
                when {
                    count != expectedCount -> "receipt anchor count mismatch"
                    !hash.contentEquals(expectedHash) -> "receipt anchor hash mismatch"
                    else -> null
                }
            }
        } catch (e: Exception) {
            e.message ?: e.javaClass.simpleName
        }
    }

    private fun writeAnchor(recordCount: Long, lastHash: ByteArray) {
        require(lastHash.size == HASH_BYTES)
        anchorFile.parentFile?.mkdirs()
        val temp = File(anchorFile.parentFile ?: File("."), anchorFile.name + ".tmp")
        RandomAccessFile(temp, "rw").use { raf ->
            raf.setLength(0)
            raf.write(ANCHOR_MAGIC)
            raf.writeLong(recordCount)
            raf.write(lastHash)
            raf.fd.sync()
        }
        try {
            Files.move(
                temp.toPath(),
                anchorFile.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (_: Exception) {
            Files.move(temp.toPath(), anchorFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)
}
