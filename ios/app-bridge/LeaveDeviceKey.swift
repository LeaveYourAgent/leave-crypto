import CryptoKit
import Foundation
import LocalAuthentication
import React
import Security

/// The device key from API contract section 1: a P-256 key in the Secure Enclave, never
/// exported, gated by the device's biometry (current set) or passcode. It signs device
/// approvals and destructive-action confirmations (X-Leave-Confirm, section 4).
///
/// CryptoKit's Secure Enclave keys are ephemeral objects; what persists is the key's
/// `dataRepresentation`, an encrypted blob only this device's enclave can restore. It is
/// kept in the Keychain, after-first-unlock, this device only, never synced.
///
/// JS surface (all promises):
///   publicKey()            → base64url (no padding) of the SPKI DER, creating the key on first use
///   sign(message, reason)  → base64url (no padding) of the DER ECDSA signature over SHA-256(message);
///                            `message` is base64url; `reason` is the biometric prompt text
///   reset()                → forgets both keys (sign-out of the last device, account deletion)
///   agreementPublicKey()   → base64url SPKI DER of a second enclave key, for key agreement only.
///                            CryptoKit types an enclave key as signing or key agreement, so the
///                            key an approving phone wraps the athlete's share to (HPKE) is its own
///                            key; it never signs anything. Opening a wrapped share with it happens
///                            natively (LeaveCrypto.acceptShare), so the share never reaches JS.
@objc(LeaveDeviceKey)
final class LeaveDeviceKey: NSObject, RCTBridgeModule {
  static func moduleName() -> String! { "LeaveDeviceKey" }
  static func requiresMainQueueSetup() -> Bool { false }

  private static let service = "com.leaveyouragent.leave.device-key"
  private static let account = "device"

  // MARK: - JS methods

  @objc func publicKey(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
      let key = try Self.loadOrCreate(context: nil)
      resolve(Self.base64url(key.publicKeyDER))
    } catch {
      reject("device_key", Self.explain(error), error)
    }
  }

  @objc func sign(_ message: String, reason: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    guard let data = Self.fromBase64url(message) else {
      reject("device_key", "Message is not base64url.", nil)
      return
    }
    let context = LAContext()
    context.localizedReason = reason
    do {
      let key = try Self.loadOrCreate(context: context)
      resolve(Self.base64url(try key.signature(for: data)))
    } catch {
      reject("device_key", Self.explain(error), error)
    }
  }

  @objc func reset(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    SecItemDelete(Self.query() as CFDictionary)
    SecItemDelete(Self.query(Self.agreementAccount) as CFDictionary)
    resolve(true)
  }

  @objc func agreementPublicKey(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    do {
      resolve(Self.base64url(try Self.loadOrCreateAgreement(context: nil).publicKeyDER))
    } catch {
      reject("device_key", Self.explain(error), error)
    }
  }

  // MARK: - Key agreement (device approval)

  private static let agreementAccount = "device-agreement"

  private enum Agreement {
    case enclave(SecureEnclave.P256.KeyAgreement.PrivateKey)
    case software(P256.KeyAgreement.PrivateKey)

    var publicKeyDER: Data {
      switch self {
      case .enclave(let k): return k.publicKey.derRepresentation
      case .software(let k): return k.publicKey.derRepresentation
      }
    }

    /// HPKE base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM; wire enc(65) ‖ ct ‖ tag.
    func open(wire: Data, info: String) throws -> Data {
      guard wire.count > 65 + 16 else { throw LeaveCryptoCore.Failure.badWire }
      let enc = wire.prefix(65)
      let ct = wire.dropFirst(65)
      switch self {
      case .enclave(let k):
        var r = try HPKE.Recipient(privateKey: k, ciphersuite: LeaveCryptoCore.hpkeSuite, info: Data(info.utf8), encapsulatedKey: enc)
        return try r.open(ct)
      case .software(let k):
        var r = try HPKE.Recipient(privateKey: k, ciphersuite: LeaveCryptoCore.hpkeSuite, info: Data(info.utf8), encapsulatedKey: enc)
        return try r.open(ct)
      }
    }
  }

  private static func loadOrCreateAgreement(context: LAContext?) throws -> Agreement {
    #if targetEnvironment(simulator)
    if let blob = readBlob(agreementAccount) {
      return .software(try P256.KeyAgreement.PrivateKey(rawRepresentation: blob))
    }
    let soft = P256.KeyAgreement.PrivateKey()
    try writeBlob(soft.rawRepresentation, agreementAccount)
    return .software(soft)
    #endif
    guard SecureEnclave.isAvailable else {
      throw NSError(domain: "LeaveDeviceKey", code: 1, userInfo: [NSLocalizedDescriptionKey: "This device has no Secure Enclave."])
    }
    if let blob = readBlob(agreementAccount) {
      return .enclave(try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context))
    }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode],
      &error
    ) else {
      throw error?.takeRetainedValue() ?? NSError(domain: "LeaveDeviceKey", code: 2)
    }
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: context)
    try writeBlob(key.dataRepresentation, agreementAccount)
    return .enclave(key)
  }

  /// Open a share an approving phone wrapped to this phone's agreement key. Native callers only.
  static func openWrappedShare(wire: Data, info: String, reason: String) throws -> Data {
    let context = LAContext()
    context.localizedReason = reason
    return try loadOrCreateAgreement(context: context).open(wire: wire, info: info)
  }

  // MARK: - Key lifecycle

  /// Either the enclave key or, on the simulator only, a software P-256 key kept in the
  /// Keychain so the flows can be driven without hardware. Release devices all have an enclave.
  private enum Signer {
    case enclave(SecureEnclave.P256.Signing.PrivateKey)
    case software(P256.Signing.PrivateKey)

    var publicKeyDER: Data {
      switch self {
      case .enclave(let k): return k.publicKey.derRepresentation
      case .software(let k): return k.publicKey.derRepresentation
      }
    }

    func signature(for data: Data) throws -> Data {
      switch self {
      case .enclave(let k): return try k.signature(for: data).derRepresentation
      case .software(let k): return try k.signature(for: data).derRepresentation
      }
    }
  }

  private static func loadOrCreate(context: LAContext?) throws -> Signer {
    #if targetEnvironment(simulator)
    // Apple Silicon simulators report an enclave, but keys gated by biometry or the
    // passcode cannot be created there ("Authentication failure"), so the simulator
    // always uses a software key.
    if let blob = readBlob() {
      return .software(try P256.Signing.PrivateKey(rawRepresentation: blob))
    }
    let soft = P256.Signing.PrivateKey()
    try writeBlob(soft.rawRepresentation)
    return .software(soft)
    #endif
    guard SecureEnclave.isAvailable else {
      throw NSError(domain: "LeaveDeviceKey", code: 1, userInfo: [NSLocalizedDescriptionKey: "This device has no Secure Enclave."])
    }
    if let blob = readBlob() {
      return .enclave(try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context))
    }
    var error: Unmanaged<CFError>?
    // Contract: biometryCurrentSet or devicePasscode, and the key is only ever used for signing.
    guard let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode],
      &error
    ) else {
      throw error?.takeRetainedValue() ?? NSError(domain: "LeaveDeviceKey", code: 2)
    }
    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
    try writeBlob(key.dataRepresentation)
    return .enclave(key)
  }

  private static func query(_ account: String = LeaveDeviceKey.account) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
    ]
  }

  private static func readBlob(_ account: String = LeaveDeviceKey.account) -> Data? {
    var q = query(account)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    return SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess ? item as? Data : nil
  }

  private static func writeBlob(_ data: Data, _ account: String = LeaveDeviceKey.account) throws {
    var add = query(account)
    add[kSecValueData as String] = data
    add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    SecItemDelete(query(account) as CFDictionary)
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Could not keep the device key (\(status))."])
    }
  }

  /// errSecAuthFailed from key creation means the phone has no passcode (and so no
  /// biometry either); the athlete can fix that themselves.
  private static func explain(_ error: Error) -> String {
    let code = (error as NSError).code
    if code == Int(errSecAuthFailed) || (error as NSError).domain == "com.apple.LocalAuthentication" {
      return "Set a passcode on this iPhone (Settings › Face ID & Passcode) to confirm actions in Leave, then try again."
    }
    return error.localizedDescription
  }

  // MARK: - Encoding

  private static func base64url(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }

  private static func fromBase64url(_ s: String) -> Data? {
    var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while b.count % 4 != 0 { b.append("=") }
    return Data(base64Encoded: b)
  }
}
