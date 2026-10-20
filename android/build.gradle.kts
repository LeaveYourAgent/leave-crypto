// The Android app's cryptography core on a plain JVM, so the shared vectors and the cross-check
// can be run without an Android device. The app itself builds the same file into the app.
plugins {
  kotlin("jvm") version "2.2.0"
}

repositories { mavenCentral() }

dependencies {
  // HPKE (RFC 9180), Argon2id (RFC 9106) and one curve multiplication; the same version the app ships.
  implementation("org.bouncycastle:bcprov-jdk18on:1.86")
  testImplementation("junit:junit:4.13.2")
  // Android has org.json built in; on a plain JVM it comes from Maven.
  testImplementation("org.json:json:20250517")
}

kotlin { jvmToolchain(17) }

tasks.test {
  // The cross-check passes its folder and phase through (cross-check/cross-check.sh).
  systemProperty("leave.cross.dir", (project.findProperty("leaveCrossDir") ?: "").toString())
  systemProperty("leave.cross.phase", (project.findProperty("leaveCrossPhase") ?: "").toString())
  testLogging { events("passed", "failed"); showStandardStreams = true }
}
