#!/usr/bin/env bash
# Offline check: compiles the Android-independent engine and report layer and runs their JUnit 5 tests
# on the JVM, without Gradle or the Android SDK. Requires kotlinc 2.x, JDK 17+, and JUnit 5 jars.
# The Android UI (app/src/main/java/com/...) is NOT compiled here; Gradle does that.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KOTLINC="${KOTLINC:-kotlinc}"
JU=/usr/share/java
JUNIT_API="$JU/junit-jupiter-api.jar:$JU/junit-jupiter-params.jar:$JU/junit-platform-commons.jar:$JU/opentest4j.jar:$JU/apiguardian-api.jar"
JUNIT_CONSOLE="$JU/junit-platform-console-standalone-1.9.1.jar"
KOTLIN_STD="$(dirname "$(command -v "$KOTLINC")")/../lib/kotlin-stdlib.jar"
OUT="$ROOT/build/jvm"
rm -rf "$OUT" && mkdir -p "$OUT/main" "$OUT/test"

echo "== compile engine + report =="
"$KOTLINC" -jvm-target 17 "$ROOT/app/src/main/java/forensics" -d "$OUT/main" 2> "$OUT/main.err" || { cat "$OUT/main.err"; echo "MAIN COMPILE FAILED"; exit 1; }
echo "== compile tests =="
"$KOTLINC" -jvm-target 17 -cp "$OUT/main:$JUNIT_API" "$ROOT/app/src/test/java/forensics" -d "$OUT/test" 2> "$OUT/test.err" || { cat "$OUT/test.err"; echo "TEST COMPILE FAILED"; exit 1; }
echo "== run tests =="
cd "$ROOT/app"
java -jar "$JUNIT_CONSOLE" --class-path "$OUT/main:$OUT/test:$JUNIT_API:$KOTLIN_STD" \
  --scan-class-path "$OUT/test" --details=summary --disable-banner --disable-ansi-colors
