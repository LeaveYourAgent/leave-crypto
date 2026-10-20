#!/bin/bash
# The same athlete on an iPhone and an Android phone, with the server between them
# (the test that held the Android app to the iPhone's before Android shipped).
#
# Three programs each play their part with their own crypto code and exchange only files:
#   iPhone   ios/Sources/LeaveCryptoCore/LeaveCryptoCore.swift itself, compiled here, on Apple's CryptoKit
#   Android  LeaveCryptoCore.kt (the Gradle test LeaveCryptoCrossCheck)
#   server   cross-check/server-crypto.mjs and Node's crypto, holding only what the real server holds
#
# What is checked, in both directions between the phones:
#   a record sealed on one phone opens on the other (the key travels wrapped to the share);
#   a record the server made opens on both (its key sealed to the account's public key);
#   each phone's proof that it holds the share verifies on the other phone and on the server;
#   each phone's grant lets the server, and only its private key, open that phone's record;
#   each phone approves the other: the share, sealed to the other phone's own key, opens there.
#
# The share is random each run, and the server's key is the test key from the shared vectors.
# This checks the crypto code only; the same exchange through the apps themselves needs signed-in
# apps on phones, which this repository doesn't run.
#
#   cross-check/cross-check.sh        (about a minute; needs Xcode's swiftc, Node and JDK 17)
set -euo pipefail
cd "$(dirname "$0")/.."
export JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home -v 17 2>/dev/null)}"

DIR=$(mktemp -d "${TMPDIR:-/tmp}/leave-crypto-cross.XXXXXX")
trap 'rm -rf "$DIR"' EXIT

node -e '
  const { randomBytes } = require("node:crypto"), fs = require("node:fs");
  const grant = JSON.parse(fs.readFileSync("vectors/v1.json", "utf8")).grant[0];
  fs.writeFileSync(process.argv[1] + "/common.json", JSON.stringify({
    share: randomBytes(32).toString("base64url"), accountId: "01J8Z3V4Q6X7R2M9K5T0W1ACCT",
    rsaPublicKeySpki: grant.rsaPublicKeySpki, rsaPrivateKeyPkcs8: grant.rsaPrivateKeyPkcs8 }));
' "$DIR"

# The iPhone app's own file, minus the one import this check does not build (libsodium, used only
# by the recovery code, which the shared vectors cover).
grep -v '^import Sodium$' ios/Sources/LeaveCryptoCore/LeaveCryptoCore.swift > "$DIR/LeaveCryptoCore.swift"
cp cross-check/ios-main.swift "$DIR/main.swift"
swiftc -O -o "$DIR/ios-cross" "$DIR/LeaveCryptoCore.swift" "$DIR/main.swift" 2> "$DIR/swiftc.log" || { cat "$DIR/swiftc.log"; exit 1; }

android() {
  (cd android && ./gradlew -q test --rerun-tasks --tests '*LeaveCryptoCrossCheck*' \
    -PleaveCrossDir="$DIR" -PleaveCrossPhase="$1" -i 2>&1 | grep -o 'Android  .*' ) \
    || { echo "Android  FAILED in phase $1 (android/build/reports/tests/test/index.html)"; exit 1; }
}

node cross-check/server.mjs make "$DIR"
"$DIR/ios-cross" make "$DIR"
android make
"$DIR/ios-cross" check "$DIR"
android check
node cross-check/server.mjs check "$DIR"
"$DIR/ios-cross" finish "$DIR"
android finish
echo "crypto cross-check: everything one side sealed, the other sides opened"
