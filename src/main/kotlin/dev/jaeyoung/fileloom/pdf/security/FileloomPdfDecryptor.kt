package dev.jaeyoung.fileloom.pdf.security

import dev.jaeyoung.fileloom.pdf.document.PdfDocumentReader
import dev.jaeyoung.fileloom.pdf.source.PdfByteSource
import dev.jaeyoung.fileloom.pdf.syntax.PdfObject
import java.io.File
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

public object FileloomPdfDecryptor {
    public fun inspect(input: PdfSecurityInput): PdfSecurityInspection {
        return openSecurityContext(input).fold(
            onSuccess = { context -> context.inspection },
            onFailure = { t -> PdfSecurityInspection.Malformed(t.message ?: t.javaClass.simpleName) }
        )
    }

    public fun decryptToFile(
        input: PdfSecurityInput,
        password: CharArray,
        output: File,
        options: PdfDecryptOptions = PdfDecryptOptions()
    ): PdfDecryptResult {
        return try {
            if (output.exists() && !options.overwriteOutput) {
                return PdfDecryptResult.IoFailure(IllegalStateException("Output already exists"))
            }
            if (input.exceedsMaxInputBytes(options.maxInputBytes)) {
                return PdfDecryptResult.UnsupportedEncryption("Input exceeds maxInputBytes")
            }

            val context = openSecurityContext(input).getOrElse { t ->
                return PdfDecryptResult.MalformedPdf(t.message ?: t.javaClass.simpleName)
            }
            val security = context.securityDictionary
                ?: return PdfDecryptResult.UnsupportedEncryption("PDF is not encrypted")
            if (context.inspection !is PdfSecurityInspection.Encrypted) {
                return PdfDecryptResult.UnsupportedEncryption("PDF is not encrypted")
            }
            if (security.filter != "Standard") {
                return PdfDecryptResult.UnsupportedEncryption("Unsupported security handler: ${security.filter}")
            }
            val cipherMethod = security.cipherMethod
            if (cipherMethod == PdfObjectCipherMethod.Unsupported) {
                return PdfDecryptResult.UnsupportedEncryption(
                    "Unsupported Standard security handler V=${security.version} R=${security.revision}"
                )
            }
            val fileId = context.fileId
                ?: return PdfDecryptResult.MalformedPdf("Missing trailer /ID for encrypted PDF")
            val fileKey = computeFileKey(password, security, fileId)
            val validPassword = validateUserPassword(fileKey, security, fileId)
            if (!validPassword) {
                return PdfDecryptResult.InvalidPassword
            }

            val inputBytes = input.readAllBytesBounded(options.maxInputBytes)
            val decrypted = rewriteClassicPdfWithoutEncryption(
                inputBytes = inputBytes,
                fileKey = fileKey,
                cipherMethod = cipherMethod,
                encryptObjectNumber = context.encryptObjectNumber
            )

            output.parentFile?.mkdirs()
            val tmp = File(output.parentFile ?: File("."), "${output.name}.tmp-${System.nanoTime()}")
            try {
                tmp.writeBytes(decrypted)
                Files.move(
                    tmp.toPath(),
                    output.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE
                )
            } catch (_: UnsupportedOperationException) {
                Files.move(tmp.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING)
            } finally {
                tmp.delete()
            }
            PdfDecryptResult.Success(
                outputFile = output,
                inspection = context.inspection,
                decryptedObjectCount = countIndirectObjects(decrypted.toString(Charsets.ISO_8859_1))
            )
        } catch (t: Throwable) {
            output.delete()
            PdfDecryptResult.IoFailure(t)
        } finally {
            password.fill('\u0000')
        }
    }

    private fun openSecurityContext(input: PdfSecurityInput): Result<PdfSecurityContext> {
        return runCatching {
            input.useByteSource { source ->
                PdfDocumentReader.open(source).use { document ->
                    val encryptObject = document.trailer.entries["Encrypt"]
                    if (encryptObject == null) {
                        return@useByteSource PdfSecurityContext(
                            inspection = PdfSecurityInspection.NotEncrypted,
                            securityDictionary = null,
                            fileId = null,
                            encryptObjectNumber = null
                        )
                    }
                    val encryptObjectNumber = (encryptObject as? PdfObject.Reference)?.objectNumber
                    val encryptDictionary = when (encryptObject) {
                        is PdfObject.Reference -> document.resolve(encryptObject) as? PdfObject.Dictionary
                        is PdfObject.Dictionary -> encryptObject
                        else -> null
                    } ?: return@useByteSource PdfSecurityContext(
                        inspection = PdfSecurityInspection.Malformed("Invalid /Encrypt entry"),
                        securityDictionary = null,
                        fileId = firstTrailerFileId(document.trailer),
                        encryptObjectNumber = encryptObjectNumber
                    )
                    val securityDictionary = parseSecurityDictionary(encryptDictionary)
                    PdfSecurityContext(
                        inspection = inspectEncryptionDictionary(securityDictionary),
                        securityDictionary = securityDictionary,
                        fileId = firstTrailerFileId(document.trailer),
                        encryptObjectNumber = encryptObjectNumber
                    )
                }
            }
        }
    }

    private fun inspectEncryptionDictionary(security: StandardSecurityDictionary): PdfSecurityInspection.Encrypted {
        val algorithm = if (security.filter != "Standard") {
            PdfEncryptionAlgorithm.Unsupported
        } else {
            classifyStandardAlgorithm(security.version, security.revision, security.keyLengthBits)
        }
        return PdfSecurityInspection.Encrypted(
            handler = security.filter,
            version = security.version,
            revision = security.revision,
            keyLengthBits = security.keyLengthBits,
            algorithm = algorithm,
            permissions = security.permissions
        )
    }

    private fun parseSecurityDictionary(dictionary: PdfObject.Dictionary): StandardSecurityDictionary {
        val entries = dictionary.entries
        val version = intValue(entries["V"])
        return StandardSecurityDictionary(
            filter = (entries["Filter"] as? PdfObject.Name)?.value,
            version = version,
            revision = intValue(entries["R"]),
            keyLengthBits = intValue(entries["Length"]) ?: defaultKeyLengthBits(version),
            permissions = intValue(entries["P"]),
            ownerEntry = bytesValue(entries["O"]) ?: ByteArray(0),
            userEntry = bytesValue(entries["U"]) ?: ByteArray(0),
            encryptMetadata = (entries["EncryptMetadata"] as? PdfObject.BooleanValue)?.value ?: true,
            cipherMethod = resolveCipherMethod(entries, version, intValue(entries["R"]))
        )
    }

    private fun intValue(value: PdfObject?): Int? = (value as? PdfObject.IntegerValue)?.value?.toInt()

    private fun bytesValue(value: PdfObject?): ByteArray? = (value as? PdfObject.StringValue)?.bytes

    private fun resolveCipherMethod(
        entries: Map<String, PdfObject>,
        version: Int?,
        revision: Int?
    ): PdfObjectCipherMethod {
        if (version == 1 && revision == 2) return PdfObjectCipherMethod.Rc4
        if (version == 2 && (revision == 3 || revision == 4)) return PdfObjectCipherMethod.Rc4
        if (version == 4 && revision == 4) {
            val stringFilter = (entries["StrF"] as? PdfObject.Name)?.value ?: "Identity"
            val cryptFilters = entries["CF"] as? PdfObject.Dictionary ?: return PdfObjectCipherMethod.Unsupported
            val selectedFilter = cryptFilters.entries[stringFilter] as? PdfObject.Dictionary
                ?: return PdfObjectCipherMethod.Unsupported
            return when ((selectedFilter.entries["CFM"] as? PdfObject.Name)?.value) {
                "AESV2" -> PdfObjectCipherMethod.AesV2
                "V2" -> PdfObjectCipherMethod.Rc4
                else -> PdfObjectCipherMethod.Unsupported
            }
        }
        return PdfObjectCipherMethod.Unsupported
    }

    private fun firstTrailerFileId(trailer: PdfObject.Dictionary): ByteArray? {
        val idArray = trailer.entries["ID"] as? PdfObject.ArrayValue ?: return null
        return bytesValue(idArray.items.firstOrNull())
    }

    private fun defaultKeyLengthBits(version: Int?): Int? {
        return when (version) {
            1 -> 40
            else -> null
        }
    }

    private fun classifyStandardAlgorithm(
        version: Int?,
        revision: Int?,
        keyLengthBits: Int?
    ): PdfEncryptionAlgorithm {
        return when {
            version == 1 || revision == 2 -> PdfEncryptionAlgorithm.Standard40Bit
            version == 2 || version == 3 -> PdfEncryptionAlgorithm.Standard128Bit
            version == 4 && keyLengthBits == 128 -> PdfEncryptionAlgorithm.Standard128Bit
            version == 5 -> PdfEncryptionAlgorithm.Standard256Bit
            else -> PdfEncryptionAlgorithm.Unsupported
        }
    }

    private fun computeFileKey(
        password: CharArray,
        security: StandardSecurityDictionary,
        fileId: ByteArray
    ): ByteArray {
        return when (security.revision) {
            2 -> computeR2FileKey(password, security.ownerEntry, security.permissions, fileId)
            3, 4 -> computeR3OrR4FileKey(
                password = password,
                ownerEntry = security.ownerEntry,
                permissions = security.permissions,
                fileId = fileId,
                encryptMetadata = security.encryptMetadata,
                keyLengthBits = security.keyLengthBits
            )
            else -> throw IllegalArgumentException(
                "Unsupported Standard security handler V=${security.version} R=${security.revision}"
            )
        }
    }

    private fun validateUserPassword(
        fileKey: ByteArray,
        security: StandardSecurityDictionary,
        fileId: ByteArray
    ): Boolean {
        return when (security.revision) {
            2 -> validateR2UserPassword(fileKey, security.userEntry)
            3, 4 -> validateR3OrR4UserPassword(fileKey, security.userEntry, fileId)
            else -> false
        }
    }

    private fun computeR2FileKey(
        password: CharArray,
        ownerEntry: ByteArray,
        permissions: Int?,
        fileId: ByteArray
    ): ByteArray {
        val digest = MessageDigest.getInstance("MD5")
        digest.update(padPassword(password.concatToString().toByteArray(Charsets.ISO_8859_1)))
        digest.update(ownerEntry)
        val p = permissions ?: 0
        digest.update(byteArrayOf(
            p.toByte(),
            (p ushr 8).toByte(),
            (p ushr 16).toByte(),
            (p ushr 24).toByte()
        ))
        digest.update(fileId)
        return digest.digest().copyOf(5)
    }

    private fun validateR2UserPassword(fileKey: ByteArray, userEntry: ByteArray): Boolean {
        if (userEntry.size < PASSWORD_PADDING.size) return false
        return rc4(fileKey, PASSWORD_PADDING).contentEquals(userEntry.copyOf(PASSWORD_PADDING.size))
    }

    private fun computeR3OrR4FileKey(
        password: CharArray,
        ownerEntry: ByteArray,
        permissions: Int?,
        fileId: ByteArray,
        encryptMetadata: Boolean,
        keyLengthBits: Int?
    ): ByteArray {
        val keyLengthBytes = ((keyLengthBits ?: 128) / 8).coerceIn(5, 16)
        var digest = MessageDigest.getInstance("MD5").apply {
            update(padPassword(password.concatToString().toByteArray(Charsets.ISO_8859_1)))
            update(ownerEntry)
            val p = permissions ?: 0
            update(byteArrayOf(p.toByte(), (p ushr 8).toByte(), (p ushr 16).toByte(), (p ushr 24).toByte()))
            update(fileId)
            if (!encryptMetadata) update(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()))
        }.digest().copyOf(keyLengthBytes)
        repeat(50) {
            digest = MessageDigest.getInstance("MD5").digest(digest).copyOf(keyLengthBytes)
        }
        return digest
    }

    private fun validateR3OrR4UserPassword(fileKey: ByteArray, userEntry: ByteArray, fileId: ByteArray): Boolean {
        if (userEntry.size < 16) return false
        val digest = MessageDigest.getInstance("MD5")
        digest.update(PASSWORD_PADDING)
        digest.update(fileId)
        var value = rc4(fileKey, digest.digest())
        for (round in 1..19) {
            val roundKey = fileKey.map { byte -> (byte.toInt() xor round).toByte() }.toByteArray()
            value = rc4(roundKey, value)
        }
        return value.contentEquals(userEntry.copyOf(16))
    }

    private fun rewriteClassicPdfWithoutEncryption(
        inputBytes: ByteArray,
        fileKey: ByteArray,
        cipherMethod: PdfObjectCipherMethod,
        encryptObjectNumber: Int?
    ): ByteArray {
        val inputText = inputBytes.toString(Charsets.ISO_8859_1)
        if (inputText.lineSequence().none { it.trim() == "xref" }) {
            throw IllegalArgumentException("Only classic xref PDFs are currently supported")
        }

        val objectRegex = Regex("(?s)(\\d+)\\s+(\\d+)\\s+obj\\s*(.*?)\\s*endobj")
        val objects = objectRegex.findAll(inputText).mapNotNull { match ->
            val objectNumber = match.groupValues[1].toInt()
            val generation = match.groupValues[2].toInt()
            if (encryptObjectNumber != null && objectNumber == encryptObjectNumber) return@mapNotNull null
            val body = decryptObjectBody(
                body = match.groupValues[3],
                fileKey = fileKey,
                cipherMethod = cipherMethod,
                objectNumber = objectNumber,
                generation = generation
            )
            PdfPlainObject(objectNumber, generation, body)
        }.toList()
        if (objects.isEmpty()) throw IllegalArgumentException("No indirect objects found")

        val maxObjectId = objects.maxOf { it.objectNumber }
        val offsets = IntArray(maxObjectId + 1) { -1 }
        val output = StringBuilder()
        output.append(inputText.lineSequence().firstOrNull()?.takeIf { it.startsWith("%PDF-") } ?: "%PDF-1.4")
            .append('\n')
        objects.sortedWith(compareBy<PdfPlainObject> { it.objectNumber }.thenBy { it.generation }).forEach { obj ->
            offsets[obj.objectNumber] = output.length
            output.append(obj.objectNumber).append(' ').append(obj.generation).append(" obj\n")
            output.append(obj.body).append('\n')
            output.append("endobj\n")
        }
        val startXref = output.length
        output.append("xref\n")
        output.append("0 ").append(maxObjectId + 1).append('\n')
        output.append("0000000000 65535 f \n")
        for (objectNumber in 1..maxObjectId) {
            val offset = offsets[objectNumber]
            if (offset >= 0) {
                output.append(offset.toString().padStart(10, '0')).append(" 00000 n \n")
            } else {
                output.append("0000000000 65535 f \n")
            }
        }
        output.append("trailer\n")
        output.append("<< /Size ").append(maxObjectId + 1)
        trailerBodyWithoutSizeOrEncrypt(inputText)?.let { trailerBody ->
            if (trailerBody.isNotBlank()) output.append(' ').append(trailerBody.trim())
        }
        output.append(" >>\n")
        output.append("startxref\n")
        output.append(startXref).append('\n')
        output.append("%%EOF\n")
        return output.toString().toByteArray(Charsets.ISO_8859_1)
    }

    private fun decryptObjectBody(
        body: String,
        fileKey: ByteArray,
        cipherMethod: PdfObjectCipherMethod,
        objectNumber: Int,
        generation: Int
    ): String {
        val objectKey = objectKey(fileKey, objectNumber, generation, cipherMethod)
        val stringsDecrypted = decryptStringsOutsideStreams(body, objectKey, cipherMethod)
        return decryptStreamsInObject(stringsDecrypted, objectKey, cipherMethod)
    }

    private fun decryptStreamsInObject(
        body: String,
        objectKey: ByteArray,
        cipherMethod: PdfObjectCipherMethod
    ): String {
        return Regex("(?s)(.*?stream\\r?\\n)(.*?)(\\r?\\nendstream)").replace(body) { match ->
            val beforeStream = match.groupValues[1]
            val encrypted = match.groupValues[2].toByteArray(Charsets.ISO_8859_1)
            val plainBytes = decryptObjectBytes(objectKey, encrypted, cipherMethod)
            val plain = plainBytes.toString(Charsets.ISO_8859_1)
            val beforeWithUpdatedLength = updateDirectStreamLength(beforeStream, plainBytes.size)
            "$beforeWithUpdatedLength$plain${match.groupValues[3]}"
        }
    }

    private fun decryptStringsOutsideStreams(
        body: String,
        objectKey: ByteArray,
        cipherMethod: PdfObjectCipherMethod
    ): String {
        return transformOutsideStreamData(body) { nonStreamBody ->
            val literalDecrypted = decryptLiteralStringsInObject(nonStreamBody, objectKey, cipherMethod)
            decryptHexStringsInObject(literalDecrypted, objectKey, cipherMethod)
        }
    }

    private fun transformOutsideStreamData(body: String, transform: (String) -> String): String {
        val streamRegex = Regex("(?s)stream\\r?\\n.*?\\r?\\nendstream")
        val output = StringBuilder()
        var cursor = 0
        for (match in streamRegex.findAll(body)) {
            output.append(transform(body.substring(cursor, match.range.first)))
            output.append(match.value)
            cursor = match.range.last + 1
        }
        output.append(transform(body.substring(cursor)))
        return output.toString()
    }

    private fun decryptLiteralStringsInObject(
        body: String,
        objectKey: ByteArray,
        cipherMethod: PdfObjectCipherMethod
    ): String {
        val output = StringBuilder(body.length)
        var index = 0
        while (index < body.length) {
            if (body[index] != '(') {
                output.append(body[index])
                index += 1
                continue
            }

            val parsed = parsePdfLiteralString(body, index)
            if (parsed == null) {
                output.append(body[index])
                index += 1
                continue
            }
            val plain = decryptObjectBytes(objectKey, parsed.bytes, cipherMethod)
            output.append(plain.toPdfLiteralString())
            index = parsed.endExclusive
        }
        return output.toString()
    }

    private fun decryptHexStringsInObject(
        body: String,
        objectKey: ByteArray,
        cipherMethod: PdfObjectCipherMethod
    ): String {
        return Regex("<([0-9A-Fa-f\\s]+)>").replace(body) { match ->
            val cipherText = match.groupValues[1].filterNot { it.isWhitespace() }.hexToBytes()
            val plain = decryptObjectBytes(objectKey, cipherText, cipherMethod)
            plain.toPdfLiteralString()
        }
    }

    private fun updateDirectStreamLength(beforeStream: String, plainLength: Int): String {
        val lengthRegex = Regex("(/Length\\s+)\\d+")
        val match = lengthRegex.findAll(beforeStream).lastOrNull() ?: return beforeStream
        val prefix = match.groups[1]?.value ?: return beforeStream
        return beforeStream.replaceRange(match.range, "$prefix$plainLength")
    }

    private fun parsePdfLiteralString(text: String, start: Int): ParsedPdfLiteralString? {
        if (start >= text.length || text[start] != '(') return null

        val bytes = mutableListOf<Int>()
        var index = start + 1
        var depth = 1
        while (index < text.length) {
            when (val char = text[index]) {
                '(' -> {
                    depth += 1
                    bytes += char.code and 0xFF
                    index += 1
                }
                ')' -> {
                    depth -= 1
                    if (depth == 0) {
                        return ParsedPdfLiteralString(
                            bytes = ByteArray(bytes.size) { bytes[it].toByte() },
                            endExclusive = index + 1
                        )
                    }
                    bytes += char.code and 0xFF
                    index += 1
                }
                '\\' -> {
                    if (index + 1 >= text.length) return null
                    val next = text[index + 1]
                    when (next) {
                        'n' -> {
                            bytes += '\n'.code
                            index += 2
                        }
                        'r' -> {
                            bytes += '\r'.code
                            index += 2
                        }
                        't' -> {
                            bytes += '\t'.code
                            index += 2
                        }
                        'b' -> {
                            bytes += 0x08
                            index += 2
                        }
                        'f' -> {
                            bytes += 0x0C
                            index += 2
                        }
                        '(', ')', '\\' -> {
                            bytes += next.code and 0xFF
                            index += 2
                        }
                        '\r' -> {
                            index += if (index + 2 < text.length && text[index + 2] == '\n') 3 else 2
                        }
                        '\n' -> {
                            index += 2
                        }
                        in '0'..'7' -> {
                            var end = index + 1
                            while (end < text.length && end < index + 4 && text[end] in '0'..'7') {
                                end += 1
                            }
                            bytes += text.substring(index + 1, end).toInt(8) and 0xFF
                            index = end
                        }
                        else -> {
                            bytes += next.code and 0xFF
                            index += 2
                        }
                    }
                }
                else -> {
                    bytes += char.code and 0xFF
                    index += 1
                }
            }
        }
        return null
    }

    private fun trailerBodyWithoutSizeOrEncrypt(inputText: String): String? {
        val trailerBody = Regex("(?s)trailer\\s*<<(.*?)>>\\s*startxref")
            .find(inputText)
            ?.groupValues
            ?.get(1)
            ?: return null
        return trailerBody
            .replace(Regex("/Size\\s+\\d+"), "")
            .replace(Regex("/Encrypt\\s+\\d+\\s+\\d+\\s+R"), "")
            .replace(Regex("\\s+"), " ")
            .trim()
    }

    private fun objectKey(
        fileKey: ByteArray,
        objectNumber: Int,
        generation: Int,
        cipherMethod: PdfObjectCipherMethod
    ): ByteArray {
        val digest = MessageDigest.getInstance("MD5")
        digest.update(fileKey)
        digest.update(byteArrayOf(
            objectNumber.toByte(),
            (objectNumber ushr 8).toByte(),
            (objectNumber ushr 16).toByte(),
            generation.toByte(),
            (generation ushr 8).toByte()
        ))
        if (cipherMethod == PdfObjectCipherMethod.AesV2) {
            digest.update(byteArrayOf('s'.code.toByte(), 'A'.code.toByte(), 'l'.code.toByte(), 'T'.code.toByte()))
        }
        return digest.digest().copyOf((fileKey.size + 5).coerceAtMost(16))
    }

    private fun decryptObjectBytes(
        objectKey: ByteArray,
        cipherText: ByteArray,
        cipherMethod: PdfObjectCipherMethod
    ): ByteArray {
        return when (cipherMethod) {
            PdfObjectCipherMethod.Rc4 -> rc4(objectKey, cipherText)
            PdfObjectCipherMethod.AesV2 -> {
                require(cipherText.size >= 16) { "AESV2 object data is missing IV" }
                val iv = cipherText.copyOfRange(0, 16)
                val encrypted = cipherText.copyOfRange(16, cipherText.size)
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(objectKey, "AES"), IvParameterSpec(iv))
                cipher.doFinal(encrypted)
            }
            PdfObjectCipherMethod.Unsupported -> throw IllegalArgumentException("Unsupported object cipher")
        }
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

    private fun countIndirectObjects(text: String): Int = Regex("(?m)^\\d+\\s+\\d+\\s+obj\\b").findAll(text).count()

    private val PASSWORD_PADDING = byteArrayOf(
        0x28, 0xBF.toByte(), 0x4E, 0x5E, 0x4E, 0x75, 0x8A.toByte(), 0x41,
        0x64, 0x00, 0x4E, 0x56, 0xFF.toByte(), 0xFA.toByte(), 0x01, 0x08,
        0x2E, 0x2E, 0x00, 0xB6.toByte(), 0xD0.toByte(), 0x68, 0x3E, 0x80.toByte(),
        0x2F, 0x0C, 0xA9.toByte(), 0xFE.toByte(), 0x64, 0x53, 0x69, 0x7A
    )
}

public data class PdfDecryptOptions(
    val overwriteOutput: Boolean = false,
    val maxInputBytes: Long? = null
)

public sealed interface PdfDecryptResult {
    public data class Success(
        val outputFile: File,
        val inspection: PdfSecurityInspection.Encrypted,
        val decryptedObjectCount: Int
    ) : PdfDecryptResult

    public data object PasswordRequired : PdfDecryptResult
    public data object InvalidPassword : PdfDecryptResult
    public data class UnsupportedEncryption(val reason: String) : PdfDecryptResult
    public data class MalformedPdf(val reason: String) : PdfDecryptResult
    public data class IoFailure(val throwable: Throwable) : PdfDecryptResult
}

public sealed interface PdfSecurityInput {
    public data class FileInput(val file: File) : PdfSecurityInput
    public data class ByteSourceInput(val source: PdfSecurityByteSource) : PdfSecurityInput
}

public interface PdfSecurityByteSource : AutoCloseable {
    public val length: Long
    public fun read(position: Long, sink: ByteArray, offset: Int, byteCount: Int): Int
    override fun close() {}
}

public sealed interface PdfSecurityInspection {
    public data object NotEncrypted : PdfSecurityInspection
    public data class Encrypted(
        val handler: String?,
        val version: Int?,
        val revision: Int?,
        val keyLengthBits: Int?,
        val algorithm: PdfEncryptionAlgorithm,
        val permissions: Int?
    ) : PdfSecurityInspection
    public data class Malformed(val reason: String) : PdfSecurityInspection
}

public enum class PdfEncryptionAlgorithm {
    Standard40Bit,
    Standard128Bit,
    Standard256Bit,
    Unsupported
}

private data class PdfSecurityContext(
    val inspection: PdfSecurityInspection,
    val securityDictionary: StandardSecurityDictionary?,
    val fileId: ByteArray?,
    val encryptObjectNumber: Int?
)

private data class StandardSecurityDictionary(
    val filter: String?,
    val version: Int?,
    val revision: Int?,
    val keyLengthBits: Int?,
    val permissions: Int?,
    val ownerEntry: ByteArray,
    val userEntry: ByteArray,
    val encryptMetadata: Boolean,
    val cipherMethod: PdfObjectCipherMethod
)

private enum class PdfObjectCipherMethod {
    Rc4,
    AesV2,
    Unsupported
}

private data class PdfPlainObject(
    val objectNumber: Int,
    val generation: Int,
    val body: String
)

private data class ParsedPdfLiteralString(
    val bytes: ByteArray,
    val endExclusive: Int
)

private inline fun <T> PdfSecurityInput.useByteSource(block: (PdfByteSource) -> T): T {
    return when (this) {
        is PdfSecurityInput.FileInput -> FileInputStream(file).channel.use { channel ->
            block(FileChannelPdfByteSource(channel))
        }
        is PdfSecurityInput.ByteSourceInput -> source.use { securitySource ->
            block(SecurityPdfByteSourceAdapter(securitySource))
        }
    }
}

private fun PdfSecurityInput.exceedsMaxInputBytes(maxInputBytes: Long?): Boolean {
    val limit = maxInputBytes ?: return false
    val length = when (this) {
        is PdfSecurityInput.FileInput -> file.length()
        is PdfSecurityInput.ByteSourceInput -> source.use { it.length }
    }
    return length > limit
}

private fun PdfSecurityInput.readAllBytesBounded(maxInputBytes: Long?): ByteArray {
    return when (this) {
        is PdfSecurityInput.FileInput -> {
            val size = file.length()
            requireAllowedInputSize(size, maxInputBytes)
            file.readBytes()
        }
        is PdfSecurityInput.ByteSourceInput -> source.use { securitySource ->
            val length = securitySource.length
            requireAllowedInputSize(length, maxInputBytes)
            if (length > Int.MAX_VALUE.toLong()) {
                throw IllegalArgumentException("Input is too large")
            }
            val output = ByteArray(length.toInt())
            var position = 0
            while (position < output.size) {
                val read = securitySource.read(position.toLong(), output, position, output.size - position)
                if (read <= 0) break
                position += read
            }
            output.copyOf(position)
        }
    }
}

private fun requireAllowedInputSize(size: Long, maxInputBytes: Long?) {
    if (size < 0) throw IllegalArgumentException("Input length must be non-negative")
    if (maxInputBytes != null && size > maxInputBytes) {
        throw IllegalArgumentException("Input exceeds maxInputBytes")
    }
}

private class FileChannelPdfByteSource(
    private val channel: FileChannel
) : PdfByteSource {
    override val length: Long = channel.size()

    override fun read(position: Long, sink: ByteArray, offset: Int, byteCount: Int): Int {
        require(position >= 0) { "position must be >= 0" }
        require(offset >= 0) { "offset must be >= 0" }
        require(byteCount >= 0) { "byteCount must be >= 0" }
        require(offset <= sink.size) { "offset must be <= sink.size" }
        require(byteCount <= sink.size - offset) { "offset + byteCount must be <= sink.size" }
        if (byteCount == 0) return 0
        if (position >= length) return -1
        return channel.read(ByteBuffer.wrap(sink, offset, byteCount), position)
    }
}

private class SecurityPdfByteSourceAdapter(
    private val source: PdfSecurityByteSource
) : PdfByteSource {
    override val length: Long get() = source.length

    override fun read(position: Long, sink: ByteArray, offset: Int, byteCount: Int): Int =
        source.read(position, sink, offset, byteCount)

    override fun close() {
        source.close()
    }
}

private fun String.hexToBytes(): ByteArray {
    val normalized = if (length % 2 == 0) this else this + "0"
    return ByteArray(normalized.length / 2) { index ->
        normalized.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
}

private fun ByteArray.toPdfLiteralString(): String {
    val builder = StringBuilder("(")
    for (byte in this) {
        when (val value = byte.toInt() and 0xFF) {
            '('.code, ')'.code, '\\'.code -> builder.append('\\').append(value.toChar())
            '\n'.code -> builder.append("\\n")
            '\r'.code -> builder.append("\\r")
            '\t'.code -> builder.append("\\t")
            else -> builder.append(value.toChar())
        }
    }
    return builder.append(')').toString()
}
