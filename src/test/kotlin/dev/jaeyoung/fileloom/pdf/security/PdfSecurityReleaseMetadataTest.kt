package dev.jaeyoung.fileloom.pdf.security

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

class PdfSecurityReleaseMetadataTest {
    @Test
    fun releaseMetadataTargetsStreamingVersion() {
        val properties = findRepositoryFile("gradle.properties").readText()
        val readme = findRepositoryFile("README.md").readText()

        assertTrue(properties.lineSequence().any { it == "version=0.1.4" })
        assertTrue(readme.contains("fileloom-pdf-security-core:0.1.4"))
        assertTrue(readme.contains("64 KiB streaming decryption"))
    }

    private fun findRepositoryFile(relativePath: String): File {
        var current: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (current != null) {
            val file = File(current, relativePath)
            if (file.isFile) return file
            current = current.parentFile
        }
        error("Unable to locate $relativePath")
    }
}
