package dev.jaeyoung.fileloom.pdf.security

import java.io.File
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class FileloomPdfDecryptorTest {
    @Test
    fun decryptToFileRejectsWrongPasswordWithoutLeavingOutput() {
        val encrypted = writeR2EncryptedPdf(userPassword = "fileloom", plaintextTitle = "Secret title")
        val output = File.createTempFile("fileloom-decrypted-wrong", ".pdf").apply { delete() }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(encrypted),
            password = "wrong".toCharArray(),
            output = output
        )

        assertEquals(PdfDecryptResult.InvalidPassword, result)
        assertFalse(output.exists())
    }

    @Test
    fun decryptToFileDecryptsLiteralStrings() {
        val encrypted = writeR2EncryptedPdf(
            userPassword = "fileloom",
            plaintextTitle = "Literal secret",
            titleAsLiteral = true
        )
        val output = File.createTempFile("fileloom-decrypted-literal", ".pdf").apply { delete() }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(encrypted),
            password = "fileloom".toCharArray(),
            output = output
        )

        assertIs<PdfDecryptResult.Success>(result, result.toString())
        val outputText = output.readText(Charsets.ISO_8859_1)
        assertTrue(outputText.contains("(Literal secret)"), outputText)
        assertFalse(outputText.contains("/Encrypt"))
    }

    @Test
    fun decryptToFileDecryptsR2Rc4Streams() {
        val encrypted = writeR2EncryptedPdf(
            userPassword = "fileloom",
            plaintextTitle = "Secret title",
            plaintextStream = "Hello stream"
        )
        val output = File.createTempFile("fileloom-decrypted-stream", ".pdf").apply { delete() }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(encrypted),
            password = "fileloom".toCharArray(),
            output = output
        )

        assertIs<PdfDecryptResult.Success>(result, result.toString())
        val outputText = output.readText(Charsets.ISO_8859_1)
        assertTrue(outputText.contains("Hello stream"), outputText)
        assertFalse(outputText.contains("/Encrypt"))
    }

    @Test
    fun decryptToFileWritesUnencryptedPdfForR3Rc4Fixture() {
        val encrypted = writeR3Rc4EncryptedPdf(userPassword = "fileloom", plaintextTitle = "RC4 128 title")
        val output = File.createTempFile("fileloom-decrypted-r3", ".pdf").apply { delete() }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(encrypted),
            password = "fileloom".toCharArray(),
            output = output
        )

        assertIs<PdfDecryptResult.Success>(result, result.toString())
        val outputText = output.readText(Charsets.ISO_8859_1)
        assertFalse(outputText.contains("/Encrypt"))
        assertTrue(outputText.contains("(RC4 128 title)"), outputText)
    }

    @Test
    fun decryptToFileUpdatesAesStreamLengthAfterDecrypting() {
        val encrypted = writeR4AesEncryptedPdf(
            userPassword = "fileloom",
            plaintextTitle = "AES title",
            plaintextStream = "Short"
        )
        val output = File.createTempFile("fileloom-decrypted-aes-stream", ".pdf").apply { delete() }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(encrypted),
            password = "fileloom".toCharArray(),
            output = output
        )

        assertIs<PdfDecryptResult.Success>(result, result.toString())
        val outputText = output.readText(Charsets.ISO_8859_1)
        assertTrue(outputText.contains("/Length 5"), outputText)
        assertTrue(outputText.contains("stream\nShort\nendstream"), outputText)
        assertFalse(outputText.contains("/Encrypt"))
    }

    @Test
    fun decryptToFileWritesUnencryptedPdfForR4AesV2Fixture() {
        val encrypted = writeR4AesEncryptedPdf(userPassword = "fileloom", plaintextTitle = "AES title")
        val output = File.createTempFile("fileloom-decrypted-aes", ".pdf").apply { delete() }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(encrypted),
            password = "fileloom".toCharArray(),
            output = output
        )

        assertIs<PdfDecryptResult.Success>(result, result.toString())
        val outputText = output.readText(Charsets.ISO_8859_1)
        assertFalse(outputText.contains("/Encrypt"))
        assertTrue(outputText.contains("(AES title)"), outputText)
    }

    @Test
    fun decryptToFileWritesUnencryptedPdfForR2Rc4Fixture() {
        val encrypted = writeR2EncryptedPdf(userPassword = "fileloom", plaintextTitle = "Secret title")
        val output = File.createTempFile("fileloom-decrypted-r2", ".pdf").apply { delete() }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(encrypted),
            password = "fileloom".toCharArray(),
            output = output
        )

        val success = assertIs<PdfDecryptResult.Success>(result, result.toString())
        assertEquals(output, success.outputFile)
        assertTrue(output.exists())
        assertEquals(PdfSecurityInspection.NotEncrypted, FileloomPdfDecryptor.inspect(PdfSecurityInput.FileInput(output)))
        val outputText = output.readText(Charsets.ISO_8859_1)
        assertFalse(outputText.contains("/Encrypt"))
        assertTrue(outputText.contains("(Secret title)"), outputText)
    }

    private fun writeR2EncryptedPdf(
        userPassword: String,
        plaintextTitle: String,
        plaintextStream: String? = null,
        titleAsLiteral: Boolean = false
    ): File {
        val ownerEntry = ByteArray(32) { index -> (0xA0 + index).toByte() }
        val fileId = ByteArray(16) { index -> (0x10 + index).toByte() }
        val permissions = -4
        val fileKey = computeR2FileKey(userPassword, ownerEntry, permissions, fileId)
        val userEntry = rc4(fileKey, PASSWORD_PADDING)
        val encryptedTitle = rc4(objectKey(fileKey, objectNumber = 4, generation = 0), plaintextTitle.toByteArray(Charsets.ISO_8859_1))
        val encryptedTitleObject = if (titleAsLiteral) {
            encryptedTitle.toPdfLiteralString()
        } else {
            "<${encryptedTitle.toHex()}>"
        }
        val objects = mutableListOf(
            1 to "<< /Type /Catalog /Pages 2 0 R >>",
            2 to "<< /Type /Pages /Count 0 >>",
            4 to "<< /Title $encryptedTitleObject >>",
            5 to "<< /Filter /Standard /V 1 /R 2 /P $permissions /O <${ownerEntry.toHex()}> /U <${userEntry.toHex()}> >>"
        )
        plaintextStream?.let { stream ->
            val encryptedStream = rc4(
                objectKey(fileKey, objectNumber = 6, generation = 0),
                stream.toByteArray(Charsets.ISO_8859_1)
            )
            objects += 6 to "<< /Length ${encryptedStream.size} >>\nstream\n${encryptedStream.toLatin1String()}\nendstream"
        }

        return writePdf(
            *objects.toTypedArray(),
            trailerExtra = "/Info 4 0 R /Encrypt 5 0 R /ID [<${fileId.toHex()}> <${fileId.toHex()}>]"
        )
    }

    private fun writeR3Rc4EncryptedPdf(userPassword: String, plaintextTitle: String): File {
        val ownerEntry = ByteArray(32) { index -> (0xC0 + index).toByte() }
        val fileId = ByteArray(16) { index -> (0x30 + index).toByte() }
        val permissions = -4
        val fileKey = computeR4FileKey(userPassword, ownerEntry, permissions, fileId, encryptMetadata = true)
        val userEntry = computeR4UserEntry(fileKey, fileId)
        val encryptedTitle = rc4(
            objectKey(fileKey, objectNumber = 4, generation = 0),
            plaintextTitle.toByteArray(Charsets.ISO_8859_1)
        )

        return writePdf(
            1 to "<< /Type /Catalog /Pages 2 0 R >>",
            2 to "<< /Type /Pages /Count 0 >>",
            4 to "<< /Title <${encryptedTitle.toHex()}> >>",
            5 to "<< /Filter /Standard /V 2 /R 3 /Length 128 /P $permissions /O <${ownerEntry.toHex()}> /U <${userEntry.toHex()}> >>",
            trailerExtra = "/Info 4 0 R /Encrypt 5 0 R /ID [<${fileId.toHex()}> <${fileId.toHex()}>]"
        )
    }

    private fun writeR4AesEncryptedPdf(
        userPassword: String,
        plaintextTitle: String,
        plaintextStream: String? = null
    ): File {
        val ownerEntry = ByteArray(32) { index -> (0x70 + index).toByte() }
        val fileId = ByteArray(16) { index -> (0x40 + index).toByte() }
        val permissions = -4
        val fileKey = computeR4FileKey(userPassword, ownerEntry, permissions, fileId, encryptMetadata = true)
        val userEntry = computeR4UserEntry(fileKey, fileId)
        val encryptedTitle = aesV2Encrypt(
            objectAesKey(fileKey, objectNumber = 4, generation = 0),
            plaintextTitle.toByteArray(Charsets.ISO_8859_1),
            iv = ByteArray(16) { index -> (0x20 + index).toByte() }
        )

        val objects = mutableListOf(
            1 to "<< /Type /Catalog /Pages 2 0 R >>",
            2 to "<< /Type /Pages /Count 0 >>",
            4 to "<< /Title <${encryptedTitle.toHex()}> >>",
            5 to "<< /Filter /Standard /V 4 /R 4 /Length 128 /P $permissions /O <${ownerEntry.toHex()}> /U <${userEntry.toHex()}> /EncryptMetadata true /CF << /StdCF << /CFM /AESV2 /Length 16 >> >> /StmF /StdCF /StrF /StdCF >>"
        )
        plaintextStream?.let { stream ->
            val encryptedStream = aesV2Encrypt(
                objectAesKey(fileKey, objectNumber = 6, generation = 0),
                stream.toByteArray(Charsets.ISO_8859_1),
                iv = ByteArray(16) { index -> (0x50 + index).toByte() }
            )
            objects += 6 to "<< /Length ${encryptedStream.size} >>\nstream\n${encryptedStream.toLatin1String()}\nendstream"
        }

        return writePdf(
            *objects.toTypedArray(),
            trailerExtra = "/Info 4 0 R /Encrypt 5 0 R /ID [<${fileId.toHex()}> <${fileId.toHex()}>]"
        )
    }

    private fun writePdf(
        vararg objects: Pair<Int, String>,
        trailerExtra: String = ""
    ): File {
        val file = File.createTempFile("fileloom-security-decrypt", ".pdf")
        file.deleteOnExit()
        val sortedObjects = objects.sortedBy { it.first }
        val maxObjectId = sortedObjects.maxOf { it.first }
        val offsets = IntArray(maxObjectId + 1)
        val content = StringBuilder()
        content.append("%PDF-1.4\n")
        sortedObjects.forEach { (objectId, body) ->
            offsets[objectId] = content.length
            content.append(objectId).append(" 0 obj\n")
            content.append(body).append('\n')
            content.append("endobj\n")
        }
        val startXref = content.length
        content.append("xref\n")
        content.append("0 ").append(maxObjectId + 1).append('\n')
        content.append("0000000000 65535 f \n")
        for (objectId in 1..maxObjectId) {
            content.append(offsets[objectId].toString().padStart(10, '0')).append(" 00000 n \n")
        }
        content.append("trailer\n")
        content.append("<< /Size ").append(maxObjectId + 1).append(" /Root 1 0 R")
        if (trailerExtra.isNotBlank()) content.append(' ').append(trailerExtra)
        content.append(" >>\n")
        content.append("startxref\n")
        content.append(startXref).append('\n')
        content.append("%%EOF\n")
        file.writeText(content.toString(), Charsets.ISO_8859_1)
        return file
    }

    private fun computeR2FileKey(password: String, ownerEntry: ByteArray, permissions: Int, fileId: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("MD5")
        digest.update(padPassword(password.toByteArray(Charsets.ISO_8859_1)))
        digest.update(ownerEntry)
        digest.update(byteArrayOf(
            permissions.toByte(),
            (permissions ushr 8).toByte(),
            (permissions ushr 16).toByte(),
            (permissions ushr 24).toByte()
        ))
        digest.update(fileId)
        return digest.digest().copyOf(5)
    }

    private fun computeR4FileKey(
        password: String,
        ownerEntry: ByteArray,
        permissions: Int,
        fileId: ByteArray,
        encryptMetadata: Boolean
    ): ByteArray {
        val keyLengthBytes = 16
        var digest = MessageDigest.getInstance("MD5").apply {
            update(padPassword(password.toByteArray(Charsets.ISO_8859_1)))
            update(ownerEntry)
            update(byteArrayOf(
                permissions.toByte(),
                (permissions ushr 8).toByte(),
                (permissions ushr 16).toByte(),
                (permissions ushr 24).toByte()
            ))
            update(fileId)
            if (!encryptMetadata) update(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()))
        }.digest().copyOf(keyLengthBytes)
        repeat(50) {
            digest = MessageDigest.getInstance("MD5").digest(digest).copyOf(keyLengthBytes)
        }
        return digest
    }

    private fun computeR4UserEntry(fileKey: ByteArray, fileId: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("MD5")
        digest.update(PASSWORD_PADDING)
        digest.update(fileId)
        var value = rc4(fileKey, digest.digest())
        for (round in 1..19) {
            val roundKey = fileKey.map { byte -> (byte.toInt() xor round).toByte() }.toByteArray()
            value = rc4(roundKey, value)
        }
        return value + ByteArray(16)
    }

    private fun objectKey(fileKey: ByteArray, objectNumber: Int, generation: Int): ByteArray {
        val digest = MessageDigest.getInstance("MD5")
        digest.update(fileKey)
        digest.update(byteArrayOf(
            objectNumber.toByte(),
            (objectNumber ushr 8).toByte(),
            (objectNumber ushr 16).toByte(),
            generation.toByte(),
            (generation ushr 8).toByte()
        ))
        return digest.digest().copyOf((fileKey.size + 5).coerceAtMost(16))
    }

    private fun objectAesKey(fileKey: ByteArray, objectNumber: Int, generation: Int): ByteArray {
        val digest = MessageDigest.getInstance("MD5")
        digest.update(fileKey)
        digest.update(byteArrayOf(
            objectNumber.toByte(),
            (objectNumber ushr 8).toByte(),
            (objectNumber ushr 16).toByte(),
            generation.toByte(),
            (generation ushr 8).toByte(),
            's'.code.toByte(), 'A'.code.toByte(), 'l'.code.toByte(), 'T'.code.toByte()
        ))
        return digest.digest().copyOf((fileKey.size + 5).coerceAtMost(16))
    }

    private fun aesV2Encrypt(key: ByteArray, input: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return iv + cipher.doFinal(input)
    }

    private fun padPassword(passwordBytes: ByteArray): ByteArray {
        val output = ByteArray(32)
        val copied = passwordBytes.size.coerceAtMost(32)
        passwordBytes.copyInto(output, endIndex = copied)
        PASSWORD_PADDING.copyInto(output, destinationOffset = copied, endIndex = 32 - copied)
        return output
    }

    private fun rc4(key: ByteArray, input: ByteArray): ByteArray {
        val s = IntArray(256) { it }
        var j = 0
        for (i in 0..255) {
            j = (j + s[i] + (key[i % key.size].toInt() and 0xFF)) and 0xFF
            val tmp = s[i]
            s[i] = s[j]
            s[j] = tmp
        }
        val out = ByteArray(input.size)
        var i = 0
        j = 0
        for (index in input.indices) {
            i = (i + 1) and 0xFF
            j = (j + s[i]) and 0xFF
            val tmp = s[i]
            s[i] = s[j]
            s[j] = tmp
            val k = s[(s[i] + s[j]) and 0xFF]
            out[index] = (input[index].toInt() xor k).toByte()
        }
        return out
    }

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
        (byte.toInt() and 0xFF).toString(16).padStart(2, '0')
    }

    private fun ByteArray.toLatin1String(): String = String(this, Charsets.ISO_8859_1)

    private fun ByteArray.toPdfLiteralString(): String {
        val builder = StringBuilder("(")
        for (byte in this) {
            when (val value = byte.toInt() and 0xFF) {
                '('.code, ')'.code, '\\'.code -> builder.append('\\').append(value.toChar())
                '\n'.code -> builder.append("\\n")
                '\r'.code -> builder.append("\\r")
                '\t'.code -> builder.append("\\t")
                else -> if (value in 32..126) {
                    builder.append(value.toChar())
                } else {
                    builder.append('\\').append(value.toString(8).padStart(3, '0'))
                }
            }
        }
        return builder.append(')').toString()
    }

    private companion object {
        val PASSWORD_PADDING = byteArrayOf(
            0x28, 0xBF.toByte(), 0x4E, 0x5E, 0x4E, 0x75, 0x8A.toByte(), 0x41,
            0x64, 0x00, 0x4E, 0x56, 0xFF.toByte(), 0xFA.toByte(), 0x01, 0x08,
            0x2E, 0x2E, 0x00, 0xB6.toByte(), 0xD0.toByte(), 0x68, 0x3E, 0x80.toByte(),
            0x2F, 0x0C, 0xA9.toByte(), 0xFE.toByte(), 0x64, 0x53, 0x69, 0x7A
        )
    }
}
