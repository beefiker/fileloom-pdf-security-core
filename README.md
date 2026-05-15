# fileloom-pdf-security-core

PDF security/decryption core library for Fileloom.

Coordinates:

```kotlin
implementation("dev.jaeyoung:fileloom-pdf-security-core:0.1.0-SNAPSHOT")
```

## Requirements

- JDK 17
- Gradle

Run tests:

```bash
gradle test
```

## Goal

Provide a pure Kotlin/JVM PDF security layer that can inspect encrypted PDFs, validate passwords, and decrypt supported encrypted PDFs to an app-private temporary plaintext PDF so Fileloom can keep using its existing Android `PdfRenderer` viewer.

## Target architecture

```text
encrypted.pdf + password
  -> fileloom-pdf-security-core
  -> decrypted temp PDF in Fileloom private cache
  -> Android PdfRenderer
  -> existing Fileloom PDF viewer behavior
```

## Scope

Initial work should be strict TDD and incremental:

1. detect `/Encrypt` metadata conservatively;
2. parse Standard Security Handler dictionaries;
3. validate user passwords for common revisions;
4. decrypt strings and streams;
5. rewrite a valid unencrypted PDF;
6. integrate with Fileloom as the first password-PDF open path.

Unsupported encryption revisions should return explicit unsupported results rather than corrupting output.

## Current support

Tested with deterministic synthetic fixtures:

- Standard Security Handler R2 / V1 / RC4 40-bit.
- Standard Security Handler R3 / V2 / RC4 128-bit.
- Standard Security Handler R4 / V4 / AESV2 128-bit.
- Classic xref tables with simple indirect objects.
- Encrypted hex strings, literal strings, and simple streams.
- Rewritten stream dictionaries with direct `/Length` values updated to decrypted plaintext length.

Known unsupported areas:

- AES-256 / R5 / R6.
- XRef streams and object streams.
- Incremental update chains.
- Complex crypt filters and indirect `/Length` updates.
- Real-world encrypted fixture corpus and Android `PdfRenderer` smoke validation.
