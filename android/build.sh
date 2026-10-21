#!/bin/zsh
# Builds Nexio.apk directly with the Android SDK tools (no Gradle needed).
# Usage: ./build.sh [--install]
set -euo pipefail
cd "${0:A:h}"

SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/$(ls "$SDK/build-tools" | sort -V | tail -1)"
PLATFORM="$SDK/platforms/$(ls "$SDK/platforms" | sort -V | head -1)"
ANDROID_JAR="$PLATFORM/android.jar"
JAVA_HOME="${JAVA_HOME:-/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
OUT=build

rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/dex"

"$BT/aapt2" compile --dir res -o "$OUT/res.zip"
"$BT/aapt2" link -o "$OUT/base.apk" -I "$ANDROID_JAR" --manifest AndroidManifest.xml "$OUT/res.zip" \
  --min-sdk-version 26 --target-sdk-version 35 --version-code 1 --version-name 1.0

"$JAVA_HOME/bin/javac" --release 17 -nowarn -Xlint:none -classpath "$ANDROID_JAR" \
  -d "$OUT/classes" $(find src -name '*.java')

"$BT/d8" --release --min-api 26 --lib "$ANDROID_JAR" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')

cp "$OUT/base.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && zip -q ../unsigned.apk classes.dex)
"$BT/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"

KS="$HOME/.android/debug.keystore"
if [[ ! -f "$KS" ]]; then
  mkdir -p "$HOME/.android"
  "$JAVA_HOME/bin/keytool" -genkeypair -keystore "$KS" -storepass android -keypass android \
    -alias androiddebugkey -keyalg RSA -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
fi
PATH="$JAVA_HOME/bin:$PATH" "$BT/apksigner" sign --ks "$KS" --ks-pass pass:android \
  --out Nexio.apk "$OUT/aligned.apk"
echo "Built $(pwd)/Nexio.apk"

if [[ "${1:-}" == "--install" ]]; then
  adb install -r Nexio.apk
  adb shell pm grant com.nexio.otp android.permission.RECEIVE_SMS || true
fi
