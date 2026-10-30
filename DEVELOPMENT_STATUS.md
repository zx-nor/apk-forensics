# BLACKBOX FORENSICS — Development Status

Last updated: milestone 1 (engine core) session.

## Build environment (verified in sandbox)
See `ENVIRONMENT_REPORT.txt`. Summary:
- Works: JDK 21, Kotlin compiler 2.4.21 (SHA-256 verified), JUnit 5.10.1 console.
- Unavailable: Android SDK API 29+, Gradle, Android Gradle Plugin, Google/Maven
  repositories, emulator/device. **An Android APK cannot be built here.**

## Milestone status
| Milestone | Status |
|---|---|
| 1. Project init, architecture, database, navigation, evidence models | NOT STARTED (Android modules not written; see below) |
| 2. File identification, hashing, binary inspection, entropy, metadata | PARTIAL — identification, hashing, entropy, hex, strings DONE; metadata NOT STARTED |
| 3–7 | NOT STARTED |

## Implemented and tested (pure Kotlin, `engine/`)
- `FileSignature` — documented magic-byte table (JPEG, PNG, GIF, PDF, ZIP, GZIP, 7z,
  RAR4/5, WAV, MP3-ID3, FLAC, OGG, SQLite3, PCAP, PCAPNG, ELF, TAR).
- `FileIdentifier` — content-based identification, bounded header read (4 KiB),
  confidence levels, extension-mismatch detection, ZIP-container caveat.
- `StreamingHasher` — chunked SHA-256 with byte count.
- `Entropy` — streaming Shannon entropy with 256-bin histogram. Reports a randomness
  indicator only; no encryption verdict is exposed.
- `HexView` — bounded-window hex/ASCII rendering with positioned reads.
- `StringExtractor` — ASCII and UTF-16LE (ASCII range) strings; runs carried across
  chunk boundaries; result cap.

## Test results
- `./build_and_test.sh` → **38 tests, 38 passed, 0 failed.**
- Expected hashes and entropies are computed independently by Python (`hashlib` and a
  separate entropy implementation) in `tools/make_corpus.py`, not by the Kotlin code.
- Mutation check: deliberately breaking the entropy logarithm base and the signature
  offset logic in a scratch copy caused 6 test failures, so the suite detects real faults.

## Known limitations (current)
- OpenPGP is not identified: its single-byte packet tag matches too much unrelated data.
- Identification covers only the signatures listed above; formats such as DOCX/APK are
  reported as ZIP with a caveat, not classified further.
- The identifier does not decode or validate container structure beyond magic bytes.
- Entropy is a randomness indicator, not proof of encryption.
- UTF-16 extraction covers only the ASCII subset.

## Not yet implemented (do not treat as available)
- Android app, Gradle build, Room database, Compose UI, Storage Access Framework.
- Evidence management, hash-linked audit log, reporting (PDF/JSON).
- Encryption detection beyond magic bytes; decryption; bounded password-recovery workflow.
- File carving, archive engine, image/document/database/APK/network/media labs.
- Metadata extraction (EXIF, PDF, Office, MP3, etc.).
- Offline verification on a device.

## Exact next steps
1. Add the metadata extractor for PNG and JPEG (chunk and segment parsing), with tests.
2. Add the archive engine with decompression, recursion, and size limits.
3. Build the bounded password-recovery module: investigator-supplied wordlist, a
   user-set attempt cap, every attempt logged without recording the password itself,
   source and output hashes recorded, original evidence opened read-only.
4. Begin the Android module structure once an Android-capable environment is available.
