// swift-tools-version:5.9
// The iPhone app's cryptography core, built on its own so the shared vectors can be run against it.
import PackageDescription

let package = Package(
  name: "LeaveCryptoKit",
  platforms: [.macOS(.v14), .iOS(.v17)],
  products: [.library(name: "LeaveCryptoKit", targets: ["LeaveCryptoKit"])],
  dependencies: [
    // Argon2id for the recovery code: libsodium's crypto_pwhash, the same version the app ships.
    .package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.9.1"),
  ],
  targets: [
    .target(name: "LeaveCryptoKit", dependencies: [.product(name: "Sodium", package: "swift-sodium")], path: "Sources/LeaveCryptoCore"),
    .testTarget(name: "LeaveCryptoKitTests", dependencies: ["LeaveCryptoKit"], path: "Tests/LeaveCryptoCoreTests"),
  ]
)
