package dev.jaeyoung.fileloom.pdf.security

import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal data class StreamingAesV2Fixture(
    val encryptedFile: File,
    val password: String,
    val expectedPlaintextBytes: Long,
    val expectedPlaintextSha256: String,
)

internal object StreamingEncryptedPdfFixture {
    fun writeAesV2(
        streamPlaintextBytes: Long,
        password: String = "fileloom-stream",
        streamPrelude: String = "",
        trailerExtra: String = "",
    ): StreamingAesV2Fixture {
        require(streamPlaintextBytes >= 0L)
        val file = File.createTempFile("fileloom-security-streaming", ".pdf").apply {
            deleteOnExit()
        }
        val ownerEntry = ByteArray(32) { index -> (0x70 + index).toByte() }
        val fileId = ByteArray(16) { index -> (0x40 + index).toByte() }
        val permissions = -4
        val fileKey = computeR4FileKey(password, ownerEntry, permissions, fileId)
        val userEntry = computeR4UserEntry(fileKey, fileId)
        val streamObjectKey = objectAesKey(fileKey, objectNumber = 4, generation = 0)
        val iv = ByteArray(16) { index -> (0x20 + index).toByte() }
        val digest = MessageDigest.getInstance("SHA-256")
        val offsets = LongArray(6) { -1L }

        CountingOutputStream(BufferedOutputStream(FileOutputStream(file))).use { output ->
            output.writeLatin1("%PDF-1.4\n")
            output.writeObject(1, offsets) {
                writeLatin1("<< /Type /Catalog /Pages 2 0 R /FileloomPayload 4 0 R >>")
            }
            output.writeObject(2, offsets) {
                writeLatin1("<< /Type /Pages /Count 0 >>")
            }
            offsets[4] = output.byteCount
            val encryptedLength = 16L + ((streamPlaintextBytes / 16L) + 1L) * 16L
            output.writeLatin1("4 0 obj\n<< /Length $encryptedLength >>\n")
            output.writeLatin1(streamPrelude)
            output.writeLatin1("stream\n")
            output.write(iv)
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(streamObjectKey, "AES"),
                IvParameterSpec(iv),
            )
            val chunk = ByteArray(64 * 1024) { index -> (index * 31).toByte() }
            var remaining = streamPlaintextBytes
            while (remaining > 0L) {
                val count = minOf(remaining, chunk.size.toLong()).toInt()
                digest.update(chunk, 0, count)
                cipher.update(chunk, 0, count)?.let(output::write)
                remaining -= count
            }
            cipher.doFinal()?.let(output::write)
            output.writeLatin1("\nendstream\nendobj\n")
            output.writeObject(5, offsets) {
                writeLatin1(
                    "<< /Filter /Standard /V 4 /R 4 /Length 128 /P $permissions " +
                        "/O <${ownerEntry.toHex()}> /U <${userEntry.toHex()}> " +
                        "/EncryptMetadata true /CF << /StdCF << /CFM /AESV2 /Length 16 >> >> " +
                        "/StmF /StdCF /StrF /StdCF >>"
                )
            }

            val startXref = output.byteCount
            output.writeLatin1("xref\n0 6\n")
            output.writeLatin1("0000000000 65535 f \n")
            for (objectNumber in 1..5) {
                val offset = offsets[objectNumber]
                if (offset >= 0L) {
                    output.writeLatin1(offset.toString().padStart(10, '0') + " 00000 n \n")
                } else {
                    output.writeLatin1("0000000000 00000 f \n")
                }
            }
            output.writeLatin1(
                "trailer\n<< /Size 6 /Root 1 0 R /Encrypt 5 0 R " +
                    "/ID [<${fileId.toHex()}> <${fileId.toHex()}>]" +
                    trailerExtra.takeIf(String::isNotBlank)?.let { " $it" }.orEmpty() +
                    " >>\n" +
                    "startxref\n$startXref\n%%EOF\n"
            )
        }

        return StreamingAesV2Fixture(
            encryptedFile = file,
            password = password,
            expectedPlaintextBytes = streamPlaintextBytes,
            expectedPlaintextSha256 = digest.digest().toHex(),
        )
    }

    private fun computeR4FileKey(
        password: String,
        ownerEntry: ByteArray,
        permissions: Int,
        fileId: ByteArray,
    ): ByteArray {
        var digest = MessageDigest.getInstance("MD5").apply {
            update(padPassword(password.toByteArray(Charsets.ISO_8859_1)))
            update(ownerEntry)
            update(
                byteArrayOf(
                    permissions.toByte(),
                    (permissions ushr 8).toByte(),
                    (permissions ushr 16).toByte(),
                    (permissions ushr 24).toByte(),
                )
            )
            update(fileId)
        }.digest().copyOf(16)
        repeat(50) {
            digest = MessageDigest.getInstance("MD5").digest(digest).copyOf(16)
        }
        return digest
    }

    private fun computeR4UserEntry(fileKey: ByteArray, fileId: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("MD5").apply {
            update(PASSWORD_PADDING)
            update(fileId)
        }.digest()
        var value = rc4(fileKey, digest)
        for (round in 1..19) {
            val roundKey = fileKey.map { byte -> (byte.toInt() xor round).toByte() }.toByteArray()
            value = rc4(roundKey, value)
        }
        return value + ByteArray(16)
    }

    private fun objectAesKey(fileKey: ByteArray, objectNumber: Int, generation: Int): ByteArray {
        val digest = MessageDigest.getInstance("MD5")
        digest.update(fileKey)
        digest.update(
            byteArrayOf(
                objectNumber.toByte(),
                (objectNumber ushr 8).toByte(),
                (objectNumber ushr 16).toByte(),
                generation.toByte(),
                (generation ushr 8).toByte(),
                0x73,
                0x41,
                0x6C,
                0x54,
            )
        )
        return digest.digest().copyOf(minOf(fileKey.size + 5, 16))
    }

    private fun padPassword(passwordBytes: ByteArray): ByteArray {
        val output = ByteArray(32)
        val copied = passwordBytes.size.coerceAtMost(32)
        passwordBytes.copyInto(output, endIndex = copied)
        PASSWORD_PADDING.copyInto(output, destinationOffset = copied, endIndex = 32 - copied)
        return output
    }

    private fun rc4(key: ByteArray, input: ByteArray): ByteArray {
        val state = IntArray(256) { it }
        var j = 0
        for (i in state.indices) {
            j = (j + state[i] + (key[i % key.size].toInt() and 0xFF)) and 0xFF
            val tmp = state[i]
            state[i] = state[j]
            state[j] = tmp
        }
        val output = ByteArray(input.size)
        var i = 0
        j = 0
        input.indices.forEach { index ->
            i = (i + 1) and 0xFF
            j = (j + state[i]) and 0xFF
            val tmp = state[i]
            state[i] = state[j]
            state[j] = tmp
            output[index] = (input[index].toInt() xor state[(state[i] + state[j]) and 0xFF]).toByte()
        }
        return output
    }

    private fun CountingOutputStream.writeObject(
        objectNumber: Int,
        offsets: LongArray,
        body: CountingOutputStream.() -> Unit,
    ) {
        offsets[objectNumber] = byteCount
        writeLatin1("$objectNumber 0 obj\n")
        body()
        writeLatin1("\nendobj\n")
    }

    private val PASSWORD_PADDING = byteArrayOf(
        0x28, 0xBF.toByte(), 0x4E, 0x5E, 0x4E, 0x75, 0x8A.toByte(), 0x41,
        0x64, 0x00, 0x4E, 0x56, 0xFF.toByte(), 0xFA.toByte(), 0x01, 0x08,
        0x2E, 0x2E, 0x00, 0xB6.toByte(), 0xD0.toByte(), 0x68, 0x3E, 0x80.toByte(),
        0x2F, 0x0C, 0xA9.toByte(), 0xFE.toByte(), 0x64, 0x53, 0x69, 0x7A,
    )
}

internal data class PdfTestStreamDescriptor(
    val payloadOffset: Long,
    val length: Long,
)

internal fun findFirstStreamLength(file: File): Long = firstStreamDescriptor(file).length

internal fun sha256OfFirstStream(file: File): String {
    val descriptor = firstStreamDescriptor(file)
    val digest = MessageDigest.getInstance("SHA-256")
    RandomAccessFile(file, "r").use { input ->
        input.seek(descriptor.payloadOffset)
        val buffer = ByteArray(64 * 1024)
        var remaining = descriptor.length
        while (remaining > 0L) {
            val read = input.read(buffer, 0, minOf(remaining, buffer.size.toLong()).toInt())
            check(read > 0) { "Unexpected EOF in test stream" }
            digest.update(buffer, 0, read)
            remaining -= read
        }
    }
    return digest.digest().toHex()
}

internal fun corruptLastByteOfFirstStream(file: File) {
    val descriptor = firstStreamDescriptor(file)
    require(descriptor.length > 0L)
    RandomAccessFile(file, "rw").use { output ->
        val position = descriptor.payloadOffset + descriptor.length - 1L
        output.seek(position)
        val original = output.read()
        require(original >= 0)
        output.seek(position)
        output.write(original xor 0x01)
    }
}

private fun firstStreamDescriptor(file: File): PdfTestStreamDescriptor {
    RandomAccessFile(file, "r").use { input ->
        val prefix = ByteArray(minOf(file.length(), 1024L * 1024L).toInt())
        input.readFully(prefix)
        val text = prefix.toString(Charsets.ISO_8859_1)
        val objectStart = text.indexOf("4 0 obj")
        check(objectStart >= 0) { "Missing test stream object" }
        val marker = "stream\n"
        val streamMarker = text.indexOf(marker, objectStart)
        check(streamMarker >= 0) { "Missing test stream marker" }
        val header = text.substring(objectStart, streamMarker)
        val length = Regex("/Length\\s+(\\d+)").find(header)
            ?.groupValues?.get(1)?.toLong()
            ?: error("Missing direct test stream length")
        return PdfTestStreamDescriptor(
            payloadOffset = streamMarker.toLong() + marker.length,
            length = length,
        )
    }
}

private fun ByteArray.toHex(): String = joinToString("") { byte ->
    "%02x".format(byte.toInt() and 0xFF)
}

private fun CountingOutputStream.writeLatin1(value: String) {
    write(value.toByteArray(Charsets.ISO_8859_1))
}

private class CountingOutputStream(output: OutputStream) : FilterOutputStream(output) {
    var byteCount: Long = 0L
        private set

    override fun write(value: Int) {
        out.write(value)
        byteCount += 1L
    }

    override fun write(buffer: ByteArray, offset: Int, length: Int) {
        out.write(buffer, offset, length)
        byteCount += length
    }
}
