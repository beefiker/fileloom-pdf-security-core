package dev.jaeyoung.fileloom.pdf.security

import dev.jaeyoung.fileloom.pdf.document.PdfDocumentReader
import dev.jaeyoung.fileloom.pdf.source.PdfByteSource
import dev.jaeyoung.fileloom.pdf.syntax.PdfObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

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
        var ownedInputSpool: File? = null
        var outputTemp: File? = null
        var fileKeyToClear: ByteArray? = null
        return try {
            if (output.exists() && !options.overwriteOutput) {
                return PdfDecryptResult.IoFailure(IllegalStateException("Output already exists"))
            }
            val outputDirectory = output.absoluteFile.parentFile ?: File(".").absoluteFile
            outputDirectory.mkdirs()
            val seekableInput = stageSeekableSecurityInput(
                input = input,
                outputDirectory = outputDirectory,
                maxInputBytes = options.maxInputBytes,
            )
            ownedInputSpool = seekableInput.ownedSpool

            val context = openSecurityContext(PdfSecurityInput.FileInput(seekableInput.file)).getOrElse { t ->
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
            fileKeyToClear = fileKey
            val validPassword = validateUserPassword(fileKey, security, fileId)
            if (!validPassword) {
                return PdfDecryptResult.InvalidPassword
            }

            val layout = PdfClassicFileLayoutReader.read(seekableInput.file)
            outputTemp = File(
                outputDirectory,
                "${output.name}.tmp-${System.nanoTime()}",
            )
            val decryptedObjectCount = PdfClassicDecryptingRewriter(
                input = seekableInput.file,
                output = outputTemp,
                layout = layout,
                fileKey = fileKey,
                cipherMethod = cipherMethod,
                encryptObjectNumber = context.encryptObjectNumber,
            ).rewrite()

            try {
                Files.move(
                    outputTemp.toPath(),
                    output.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE,
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(
                    outputTemp.toPath(),
                    output.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: UnsupportedOperationException) {
                Files.move(
                    outputTemp.toPath(),
                    output.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                )
            }
            PdfDecryptResult.Success(
                outputFile = output,
                inspection = context.inspection,
                decryptedObjectCount = decryptedObjectCount,
            )
        } catch (error: PdfStreamingRewriteException) {
            when (error.kind) {
                PdfStreamingRewriteFailureKind.Unsupported ->
                    PdfDecryptResult.UnsupportedEncryption("${error.code}: ${error.message}")
                PdfStreamingRewriteFailureKind.Malformed ->
                    PdfDecryptResult.MalformedPdf("${error.code}: ${error.message}")
            }
        } catch (error: IllegalArgumentException) {
            if (error.message == "Input exceeds maxInputBytes") {
                PdfDecryptResult.UnsupportedEncryption("Input exceeds maxInputBytes")
            } else {
                PdfDecryptResult.IoFailure(error)
            }
        } catch (t: Throwable) {
            PdfDecryptResult.IoFailure(t)
        } finally {
            outputTemp?.delete()
            ownedInputSpool?.delete()
            fileKeyToClear?.fill(0)
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

internal enum class PdfObjectCipherMethod {
    Rc4,
    AesV2,
    Unsupported
}

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

private data class SeekableSecurityInput(
    val file: File,
    val ownedSpool: File? = null,
)

private fun stageSeekableSecurityInput(
    input: PdfSecurityInput,
    outputDirectory: File,
    maxInputBytes: Long?,
): SeekableSecurityInput = when (input) {
    is PdfSecurityInput.FileInput -> {
        requireAllowedInputSize(input.file.length(), maxInputBytes)
        val spool = File.createTempFile("pdf-security-input-", ".spool", outputDirectory)
        try {
            FileInputStream(input.file).buffered().use { source ->
                FileOutputStream(spool).buffered().use { output ->
                    copyInputStreamBounded(source, output, maxInputBytes)
                }
            }
            SeekableSecurityInput(file = spool, ownedSpool = spool)
        } catch (error: Throwable) {
            spool.delete()
            throw error
        }
    }
    is PdfSecurityInput.ByteSourceInput -> {
        input.source.use { source ->
            val length = source.length
            requireAllowedInputSize(length, maxInputBytes)
            val spool = File.createTempFile("pdf-security-input-", ".spool", outputDirectory)
            try {
                FileOutputStream(spool).buffered().use { output ->
                    val buffer = ByteArray(STREAM_BUFFER_BYTES)
                    var position = 0L
                    while (position < length) {
                        val request = minOf(length - position, buffer.size.toLong()).toInt()
                        val read = source.read(position, buffer, 0, request)
                        if (read <= 0) {
                            throw IOException("Unexpected EOF while staging PDF byte source")
                        }
                        output.write(buffer, 0, read)
                        position += read
                    }
                }
                SeekableSecurityInput(file = spool, ownedSpool = spool)
            } catch (error: Throwable) {
                spool.delete()
                throw error
            }
        }
    }
}

private fun copyInputStreamBounded(
    source: java.io.InputStream,
    output: java.io.OutputStream,
    maxInputBytes: Long?,
) {
    val buffer = ByteArray(STREAM_BUFFER_BYTES)
    var copied = 0L
    while (true) {
        val request = if (maxInputBytes == null) {
            buffer.size
        } else {
            minOf(buffer.size.toLong(), (maxInputBytes - copied + 1L).coerceAtLeast(1L)).toInt()
        }
        val read = source.read(buffer, 0, request)
        if (read < 0) return
        if (read == 0) throw IOException("Input stream made no progress")
        copied += read
        requireAllowedInputSize(copied, maxInputBytes)
        output.write(buffer, 0, read)
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
