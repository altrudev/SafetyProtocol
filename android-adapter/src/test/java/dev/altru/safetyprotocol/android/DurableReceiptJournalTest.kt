package dev.altru.safetyprotocol.android

import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DurableReceiptJournalTest {
    @Test
    fun appendFsyncReopenAndVerifyHashChain() {
        val dir = Files.createTempDirectory("safetyprotocol-receipts").toFile()
        val file = File(dir, "receipts.bin")
        try {
            val journal = HashChainedReceiptJournal(file)
            journal.append(receipt(1, 10))
            journal.append(receipt(2, 11))

            val verification = HashChainedReceiptJournal(file).verify()
            assertTrue(verification.valid)
            assertEquals(2L, verification.recordCount)
            assertEquals(32, verification.lastHash.size)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun singleByteTamperIsDetected() {
        val dir = Files.createTempDirectory("safetyprotocol-receipts").toFile()
        val file = File(dir, "receipts.bin")
        try {
            val journal = HashChainedReceiptJournal(file)
            journal.append(receipt(1, 10))
            journal.append(receipt(2, 11))

            RandomAccessFile(file, "rw").use { raf ->
                val position = (raf.length() / 2).coerceAtLeast(16)
                raf.seek(position)
                val original = raf.readByte()
                raf.seek(position)
                raf.writeByte(original.toInt() xor 0x01)
                raf.fd.sync()
            }

            assertFalse(HashChainedReceiptJournal(file).verify().valid)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun truncationIsDetected() {
        val dir = Files.createTempDirectory("safetyprotocol-receipts").toFile()
        val file = File(dir, "receipts.bin")
        try {
            val journal = HashChainedReceiptJournal(file)
            journal.append(receipt(1, 10))
            journal.append(receipt(2, 11))

            RandomAccessFile(file, "rw").use { raf ->
                raf.setLength(raf.length() - 7)
                raf.fd.sync()
            }

            assertFalse(HashChainedReceiptJournal(file).verify().valid)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun appendRefusesCorruptedExistingJournal() {
        val dir = Files.createTempDirectory("safetyprotocol-receipts").toFile()
        val file = File(dir, "receipts.bin")
        try {
            val journal = HashChainedReceiptJournal(file)
            journal.append(receipt(1, 10))
            RandomAccessFile(file, "rw").use { raf ->
                raf.seek(raf.length() - 1)
                raf.writeByte(0x7f)
                raf.fd.sync()
            }

            var failed = false
            try {
                HashChainedReceiptJournal(file).append(receipt(2, 11))
            } catch (_: ReceiptJournalIntegrityException) {
                failed = true
            }
            assertTrue(failed)
        } finally {
            dir.deleteRecursively()
        }
    }


    @Test
    fun completeFinalRecordRemovalIsDetectedByAnchor() {
        val dir = Files.createTempDirectory("safetyprotocol-receipts").toFile()
        val file = File(dir, "receipts.bin")
        try {
            val journal = HashChainedReceiptJournal(file)
            journal.append(receipt(1, 10))
            val firstRecordEnd = RandomAccessFile(file, "r").use { raf ->
                raf.seek(8)
                val size = raf.readInt()
                8L + 4L + size.toLong() + 32L
            }
            journal.append(receipt(2, 11))

            RandomAccessFile(file, "rw").use { raf ->
                raf.setLength(firstRecordEnd)
                raf.fd.sync()
            }

            val verification = HashChainedReceiptJournal(file).verify()
            assertFalse(verification.valid)
            assertEquals("receipt anchor count mismatch", verification.failure)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun missingAnchorOnNonEmptyJournalIsDetected() {
        val dir = Files.createTempDirectory("safetyprotocol-receipts").toFile()
        val file = File(dir, "receipts.bin")
        val anchor = File(dir, "receipts.bin.anchor")
        try {
            val journal = HashChainedReceiptJournal(file)
            journal.append(receipt(1, 10))
            assertTrue(anchor.delete())

            val verification = HashChainedReceiptJournal(file).verify()
            assertFalse(verification.valid)
            assertEquals("receipt anchor missing", verification.failure)
        } finally {
            dir.deleteRecursively()
        }
    }


    @Test
    fun journalRefusesGrowthPastRecordCeiling() {
        val dir = Files.createTempDirectory("safetyprotocol-receipts").toFile()
        val file = File(dir, "receipts.bin")
        try {
            val journal = HashChainedReceiptJournal(file = file, maxRecords = 2, maxJournalBytes = 16_384)
            journal.append(receipt(1, 10))
            journal.append(receipt(2, 11))
            var failed = false
            try {
                journal.append(receipt(3, 12))
            } catch (_: ReceiptJournalCapacityException) {
                failed = true
            }
            assertTrue(failed)
            assertEquals(2L, journal.verify().recordCount)
        } finally {
            dir.deleteRecursively()
        }
    }


    @Test
    fun journalRefusesGrowthPastByteCeiling() {
        val dir = Files.createTempDirectory("safetyprotocol-receipts").toFile()
        val file = File(dir, "receipts.bin")
        try {
            val journal = HashChainedReceiptJournal(file = file, maxRecords = 10, maxJournalBytes = 64)
            var failed = false
            try {
                journal.append(receipt(1, 10))
            } catch (_: ReceiptJournalCapacityException) {
                failed = true
            }
            assertTrue(failed)
            assertEquals(0L, journal.verify().recordCount)
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun receipt(id: Long, sequence: Long) = ForwardingExecutionReceipt(
        permitId = id,
        revision = ForwardingExecutionRevision(3, 4),
        frameSequence = sequence,
        frameLength = 40,
        disposition = ForwardingReceiptDisposition.EXECUTED,
        reason = ForwardingExecutionReason.EXECUTED,
        issuedAtMs = 100,
        terminalAtMs = 110,
    )
}
