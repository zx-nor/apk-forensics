# BLACKBOX FORENSICS — Engine Core

Offline forensic analysis engines in pure Kotlin. The Android application is not yet
built; see `DEVELOPMENT_STATUS.md` for what exists and what does not.

## Layout
- `engine/src/main/kotlin/forensics/` — engines (identify, hash, binary)
- `engine/src/test/kotlin/forensics/` — JUnit 5 tests
- `engine/src/test/resources/corpus/` — synthetic corpus + `expected.tsv`
- `tools/make_corpus.py` — regenerates the M1 corpus and expected values
- `tools/make_fixtures_m2.py` — regenerates the M2 corpus and expected results (needs PIL, aapt2, openssl, zip)
- `build_and_test.sh` — compiles and runs all tests

## Run
Requires JDK 17+, Kotlin 2.x compiler (`KOTLINC` env var or default
`/opt/kotlin/kotlinc/bin/kotlinc`), and JUnit 5 jars under `/usr/share/java`.

    python3 tools/make_corpus.py   # optional: regenerate corpus
    ./build_and_test.sh

## Dependencies and licenses
| Component | Version | License |
|---|---|---|
| Kotlin compiler and stdlib | 2.4.21 | Apache-2.0 |
| Pillow (fixture generation only) | 12.x | HPND |
| aapt2 (fixture generation only) | Debian build | Apache-2.0 |
| OpenSSL (fixture generation only) | 3.0.13 | Apache-2.0 |
| Info-ZIP zip (fixture generation only) | 3.0 | Info-ZIP license |
| OpenJDK | 21 | GPL-2.0 with Classpath Exception |
| JUnit 5 (Jupiter API/Params, Platform Console) | 5.10.1 / 1.9.1 | EPL-2.0 |

No third-party runtime libraries are used by the engine.

## Verification
78 JUnit tests (`./build_and_test.sh`). Expected values for the corpora are computed independently
(Python hashlib/zipfile/sqlite3, PIL, aapt2, openssl, Info-ZIP) by `tools/make_corpus.py` and
`tools/make_fixtures_m2.py`. See `DEVELOPMENT_STATUS.md` for scope and limitations.
