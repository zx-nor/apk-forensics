#!/usr/bin/env bash
# Compiles the pure-Kotlin engine and runs its JUnit 5 tests.
# Requires: kotlinc (2.x), JDK 17+, JUnit 5 jars (Ubuntu package junit5).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
KOTLINC="${KOTLINC:-/opt/kotlin/kotlinc/bin/kotlinc}"
JU=/usr/share/java
JUNIT_API="$JU/junit-jupiter-api.jar:$JU/junit-jupiter-params.jar:$JU/junit-platform-commons.jar:$JU/opentest4j.jar:$JU/apiguardian-api.jar"
JUNIT_CONSOLE="$JU/junit-platform-console-standalone-1.9.1.jar"
OUT="$ROOT/build"
rm -rf "$OUT" && mkdir -p "$OUT/main" "$OUT/test"

echo "== compile main =="
"$KOTLINC" -jvm-target 17 -Werror=false "$ROOT"/engine/src/main/kotlin -d "$OUT/main" 2>&1 | grep -v "^warning:" || true
[ -d "$OUT/main/forensics" ] || { echo "MAIN COMPILE FAILED"; exit 1; }

echo "== compile tests =="
"$KOTLINC" -jvm-target 17 -cp "$OUT/main:$JUNIT_API" "$ROOT"/engine/src/test/kotlin -d "$OUT/test" 2>&1 | grep -v "^warning:" || true
[ -n "$(find "$OUT/test" -name '*.class' 2>/dev/null)" ] || { echo "TEST COMPILE FAILED"; exit 1; }

echo "== run tests =="
cp -r "$ROOT/engine/src/test/resources/." "$OUT/test/" 2>/dev/null || true
cd "$ROOT/engine"
java -jar "$JUNIT_CONSOLE" --class-path "$OUT/main:$OUT/test:$JUNIT_API:/opt/kotlin/kotlinc/lib/kotlin-stdlib.jar" \
  --scan-class-path "$OUT/test" --details=tree --disable-banner
