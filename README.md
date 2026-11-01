# BLACKBOX FORENSICS

Offline digital-forensics app for Android. Analyzes a copy of a file chosen with the system file
picker: identifies format from content, inspects structure, extracts metadata, examines archives,
and shows hashes, findings, and a hex view. Nothing is sent anywhere; no account or network is used.

## Repository layout

```
app/src/main/java/forensics/          Engine (pure Kotlin, no Android APIs): identification,
                                      ZIP analysis, metadata, binary tools, report builder
app/src/main/java/com/blackbox/forensics/   Android app: file copy, view model, Compose UI
app/src/main/AndroidManifest.xml
app/src/main/res/                     Strings and theme
app/src/test/java/forensics/          JUnit 5 tests (run on the JVM)
app/src/test/resources/corpus*/       Synthetic evidence and expected results
tools/                                Generators for the synthetic corpora
scripts/jvm-test.sh                   Offline test run without Gradle (needs kotlinc, JDK 17, JUnit 5)
.github/workflows/android.yml         CI: runs tests and builds the debug APK
docs/ENVIRONMENT_REPORT.txt           Build-environment notes from development
```

## Building the APK on GitHub

1. Create a GitHub repository and push this project to it.
2. Open the **Actions** tab. The "Build APK" workflow runs on every push.
3. When it finishes, download the `blackbox-forensics-debug-apk` artifact from the run's page.
4. Install the APK on an Android device running Android 10 (API 29) or newer. Allow installs from
   the source you used to download it.

The debug APK is signed with Android's debug key, so it installs directly but is not suitable for
distribution. A signed release build requires your own keystore, which is not included.

To build locally with Android Studio: open the project folder and run the `app` configuration.
To build from a terminal with Gradle 8.9 and JDK 17 installed: `gradle :app:assembleDebug`.

## Using the app

- Tap **Open evidence file** and choose a document.
- The app copies it into private storage, hashes the copy, and reports whether the analyzed bytes
  match the acquired bytes. The original file is only read, never written.
- The report shows identification, findings, metadata (with an explicit status for each format),
  archive entries (for ZIP-based files), appended and embedded data, a paged hex view, and strings.

## Scope and limits

See `DEVELOPMENT_STATUS.md`. In short: encryption is identified but not decrypted; 7z and RAR are
identified by signature only; APK signatures are parsed but not cryptographically verified.
