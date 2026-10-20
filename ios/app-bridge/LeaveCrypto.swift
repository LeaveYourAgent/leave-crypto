import CryptoKit
import Foundation
import React
import Security

/// The athlete's keys, held natively so JavaScript never sees the share or a data key.
///
/// - The athlete share (32 random bytes) lives in the Keychain, after first unlock,
///   synchronizable so it follows the athlete's iCloud Keychain to their next phone
///   (contract section 1).
/// - Data keys (DEKs) are generated here, kept in memory for the session, and leave the
///   process only wrapped: to the share (share wrap), to a public key (HPKE) or to the
///   server's session key (a grant).
///
/// JS surface (promises; binary values are base64url without padding; big payloads go
/// through file paths, never the bridge):
///   useAccount(accountId | null)                     → true   (names the share's Keychain slot)
///   adoptLegacyShare(accountId, publicKey)           → bool   (the one-time move, on a match)
///   ensureShare()                                    → { created }
///   accountPublicKey(accountId)                      → SPKI base64url
///   newRecordKey(type, id)                           → { shareWrappedDek }
///   importShareWrappedDek(type, id, wire)            → true
///   importPendingDek(type, id, wire, info, accountId)→ { shareWrappedDek }   (HPKE to the account key)
///   wrapDekTo(type, id, recipientSpki, info)         → HPKE wire (Teammate wrap)
///   encrypt(type, id, plaintext) / decrypt(type, id, wire)
///   encryptFile(type, id, srcPath, dstPath)          → { sha256, sizeBytes }
///   decryptFile(type, id, srcPath, dstPath)          → { sizeBytes }
///   grant(sessionId, serverSpki, exp, records)       → { body, header }
///   aliasKey(fromType, fromId, toType, toId)         → true   (same DEK, another AAD)
///   hasKey(type, id)                                 → bool
///   compareCode(key, requestId)                      → "482913"   (new phone and approving phone)
///   forgetKeys()                                     → true   (sign-out: DEKs only; the share stays)
///   deleteShare()                                    → true   (account deletion)
@objc(LeaveCrypto)
final class LeaveCrypto: NSObject, RCTBridgeModule {
  static func moduleName() -> String! { "LeaveCrypto" }
  static func requiresMainQueueSetup() -> Bool { false }

  private static let shareService = "com.leaveyouragent.leave.share"
  /// Before build 45 the share had one Keychain slot for the whole Apple Account, named
  /// "athlete". A variable only so tests use their own.
  static var legacySlot = "athlete"
  private static let lock = NSLock()
  private static var deks: [String: Data] = [:]
  /// The Leave account whose key this phone is working with. Its id names the share's slot.
  private static var account: String?

  private static func key(_ type: String, _ id: String) -> String { "\(type):\(id)" }

  private static func dek(_ type: String, _ id: String) throws -> Data {
    lock.lock(); defer { lock.unlock() }
    guard let d = deks[key(type, id)] else {
      throw NSError(domain: "LeaveCrypto", code: 10, userInfo: [NSLocalizedDescriptionKey: "No key for \(type) \(id) in this session."])
    }
    return d
  }

  private static func remember(_ type: String, _ id: String, _ dek: Data) {
    lock.lock(); deks[key(type, id)] = dek; lock.unlock()
  }

  // MARK: - Share

  /// One slot per Leave account. The share used to sit in one slot per Apple Account, and
  /// taking in an approved share deleted whatever was there, on every device the item syncs to:
  /// a parent who signed in to the athlete's account on their own phone lost the guardian
  /// account's key for good. Nothing here ever deletes or replaces another account's item.
  static func use(account id: String?) {
    lock.lock(); defer { lock.unlock() }
    if account != id {
      account = id
      deks.removeAll()
    }
  }

  private static func current() throws -> String {
    lock.lock(); defer { lock.unlock() }
    guard let a = account, !a.isEmpty else {
      throw NSError(domain: "LeaveCrypto", code: 13, userInfo: [NSLocalizedDescriptionKey: "No Leave account is signed in on this phone."])
    }
    return a
  }

  private static func shareQuery(_ slot: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: shareService,
      kSecAttrAccount as String: slot,
      kSecAttrSynchronizable as String: kCFBooleanTrue as Any,
    ]
  }

  static func loadShare(slot: String) -> Data? {
    var q = shareQuery(slot)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    return SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess ? item as? Data : nil
  }

  private static func add(_ share: Data, slot: String) -> OSStatus {
    var add = shareQuery(slot)
    add[kSecValueData as String] = share
    add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
    return SecItemAdd(add as CFDictionary, nil)
  }

  private static let noShare = NSError(domain: "LeaveCrypto", code: 12, userInfo: [NSLocalizedDescriptionKey: "This phone does not hold your key yet."])

  /// The signed-in account's own share, and nothing else: for everything that writes with it
  /// (a new record's key, a wrap for another phone). It is created only by `ensureShare` (the
  /// first phone on an account); everything else fails rather than mint a second one.
  static func ownShare() throws -> Data {
    guard let s = loadShare(slot: try current()) else { throw noShare }
    return s
  }

  /// For reading and proving only: the account's own share, or the old shared slot's while the
  /// one-time move hasn't happened (the first launch after the update, before the server has
  /// been asked). A share that isn't this account's opens nothing and proves nothing.
  private static func share() throws -> Data {
    if let own = loadShare(slot: try current()) { return own }
    guard let old = loadShare(slot: legacySlot) else { throw noShare }
    return old
  }

  /// Creates the account's share on first use. Never overwrites one, and never hands a new
  /// account the old shared slot's share (a second new account used to get the first one's).
  static func ensureShareData() throws -> (Data, Bool) {
    let slot = try current()
    if let s = loadShare(slot: slot) { return (s, false) }
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, 32, &bytes) == errSecSuccess else {
      throw NSError(domain: "LeaveCrypto", code: 11, userInfo: [NSLocalizedDescriptionKey: "Could not draw random bytes."])
    }
    let share = Data(bytes)
    let status = add(share, slot: slot)
    if status == errSecDuplicateItem, let s = loadShare(slot: slot) { return (s, false) }
    guard status == errSecSuccess else {
      throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Could not keep the share (\(status))."])
    }
    return (share, true)
  }

  /// The account key's public half, as the server holds it (SPKI DER, base64url).
  static func publicKey(of share: Data, accountId: String) throws -> String {
    LeaveCryptoCore.base64url(try LeaveCryptoCore.accountAgreementKey(share: share, accountId: accountId).publicKey.derRepresentation)
  }

  /// The one-time move: the old shared slot's share is copied into this account's slot only when
  /// it is this account's key. The old item stays: deleting a synced item reaches every device
  /// on the Apple Account, and one of them may still run a build that reads it.
  static func adoptLegacyShare(accountId: String, publicKey expected: String) throws -> Bool {
    guard !accountId.isEmpty, loadShare(slot: accountId) == nil, let old = loadShare(slot: legacySlot) else { return false }
    guard try publicKey(of: old, accountId: accountId) == expected else { return false }
    let status = add(old, slot: accountId)
    return status == errSecSuccess || status == errSecDuplicateItem
  }

  /// The share an approving phone sent (device approval), kept only if it is this account's key.
  /// Only this account's slot is replaced.
  static func accept(_ share: Data, accountId: String, publicKey expected: String) throws {
    guard share.count == 32 else { throw LeaveCryptoCore.Failure.badWire }
    guard !accountId.isEmpty, try publicKey(of: share, accountId: accountId) == expected else {
      throw NSError(domain: "LeaveCrypto", code: 14, userInfo: [NSLocalizedDescriptionKey: "The key that arrived is not this account's key. Nothing was changed."])
    }
    SecItemDelete(shareQuery(accountId) as CFDictionary)
    let status = add(share, slot: accountId)
    guard status == errSecSuccess else {
      throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Could not keep the share (\(status))."])
    }
    lock.lock(); deks.removeAll(); lock.unlock()
  }

  /// Account deletion: this account's slot, and the old shared slot only when it holds the same key.
  static func removeShare() throws {
    let slot = try current()
    let own = loadShare(slot: slot)
    SecItemDelete(shareQuery(slot) as CFDictionary)
    if let own, loadShare(slot: legacySlot) == own {
      SecItemDelete(shareQuery(legacySlot) as CFDictionary)
    }
    lock.lock(); deks.removeAll(); lock.unlock()
  }

  // MARK: - JS methods

  @objc func ensureShare(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      let (_, created) = try Self.ensureShareData()
      resolve(["created": created])
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  /// The Leave account signed in on this phone (null after sign-out). Its id names the share's slot.
  @objc func useAccount(_ accountId: String?, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    Self.use(account: accountId)
    resolve(true)
  }

  /// The one-time move from the old shared slot (see `adoptLegacyShare`).
  @objc func adoptLegacyShare(_ accountId: String, publicKey: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do { resolve(try Self.adoptLegacyShare(accountId: accountId, publicKey: publicKey)) } catch { reject("crypto", error.localizedDescription, error) }
  }

  @objc func hasShare(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    resolve((try? Self.share()) != nil)
  }

  /// Proof that this phone holds the share: the account key's signature over `message`
  /// (UTF-8; for activation, deviceId ‖ accountId). Raw r ‖ s, base64url.
  @objc func accountProof(_ accountId: String, message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      let key = try LeaveCryptoCore.accountSigningKey(share: try Self.share(), accountId: accountId)
      resolve(LeaveCryptoCore.base64url(try key.signature(for: Data(message.utf8)).rawRepresentation))
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  /// The share wrapped to another phone's agreement key (HPKE), for POST /devices/{id}/approve.
  @objc func wrapShareTo(_ recipientSpki: String, info: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let spki = LeaveCryptoCore.fromBase64url(recipientSpki) else { throw LeaveCryptoCore.Failure.badPublicKey }
      let wire = try LeaveCryptoCore.hpkeSeal(recipientSpki: spki, info: info, plaintext: try Self.ownShare())
      resolve(LeaveCryptoCore.base64url(wire))
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  /// A new phone takes the share an approving phone wrapped to it: opened with this phone's
  /// enclave agreement key (Face ID) and kept in the Keychain. It never crosses into JavaScript.
  /// It is kept only if it is this account's key (`publicKey`, as the server holds it).
  @objc func acceptShare(_ wire: String, info: String, reason: String, accountId: String, publicKey: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    DispatchQueue.global(qos: .userInitiated).async {
      do {
        guard let w = LeaveCryptoCore.fromBase64url(wire) else { throw LeaveCryptoCore.Failure.badWire }
        try Self.accept(try LeaveDeviceKey.openWrappedShare(wire: w, info: info, reason: reason), accountId: accountId, publicKey: publicKey)
        resolve(true)
      } catch { reject("crypto", error.localizedDescription, error) }
    }
  }

  @objc func accountPublicKey(_ accountId: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      resolve(try Self.publicKey(of: try Self.share(), accountId: accountId))
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  @objc func newRecordKey(_ type: String, id: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      let dek = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      Self.remember(type, id, dek)
      let wire = try LeaveCryptoCore.shareWrap(share: try Self.ownShare(), recordType: type, recordId: id, dek: dek)
      resolve(["shareWrappedDek": LeaveCryptoCore.base64url(wire)])
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  @objc func importShareWrappedDek(_ type: String, id: String, wire: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let w = LeaveCryptoCore.fromBase64url(wire) else { throw LeaveCryptoCore.Failure.badWire }
      let dek = try LeaveCryptoCore.shareUnwrap(share: try Self.share(), recordType: type, recordId: id, wire: w)
      Self.remember(type, id, dek)
      resolve(true)
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  /// A record the server created: its DEK arrives HPKE-wrapped to the account key. Unwrap it,
  /// keep it, and hand back the share wrap the app then stores with PUT /records/keys.
  @objc func importPendingDek(_ type: String, id: String, wire: String, info: String, accountId: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let w = LeaveCryptoCore.fromBase64url(wire) else { throw LeaveCryptoCore.Failure.badWire }
      let s = try Self.ownShare()
      let dek = try LeaveCryptoCore.hpkeOpen(recipientKey: try LeaveCryptoCore.accountAgreementKey(share: s, accountId: accountId), info: info, wire: w)
      Self.remember(type, id, dek)
      let rewrapped = try LeaveCryptoCore.shareWrap(share: s, recordType: type, recordId: id, dek: dek)
      resolve(["shareWrappedDek": LeaveCryptoCore.base64url(rewrapped)])
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  @objc func wrapDekTo(_ type: String, id: String, recipientSpki: String, info: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let spki = LeaveCryptoCore.fromBase64url(recipientSpki) else { throw LeaveCryptoCore.Failure.badPublicKey }
      let wire = try LeaveCryptoCore.hpkeSeal(recipientSpki: spki, info: info, plaintext: try Self.dek(type, id))
      resolve(LeaveCryptoCore.base64url(wire))
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  @objc func encrypt(_ type: String, id: String, plaintext: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let p = LeaveCryptoCore.fromBase64url(plaintext) else { throw LeaveCryptoCore.Failure.badWire }
      let wire = try LeaveCryptoCore.seal(key: try Self.dek(type, id), plaintext: p, aad: LeaveCryptoCore.aad(type, id))
      resolve(LeaveCryptoCore.base64url(wire))
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  @objc func decrypt(_ type: String, id: String, wire: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let w = LeaveCryptoCore.fromBase64url(wire) else { throw LeaveCryptoCore.Failure.badWire }
      let p = try LeaveCryptoCore.open(key: try Self.dek(type, id), wire: w, aad: LeaveCryptoCore.aad(type, id))
      resolve(LeaveCryptoCore.base64url(p))
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  /// Whole-file encryption for uploads (≤ 25 MiB, fits memory); returns what POST /uploads needs.
  @objc func encryptFile(_ type: String, id: String, srcPath: String, dstPath: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      let plain = try Data(contentsOf: URL(fileURLWithPath: srcPath))
      let wire = try LeaveCryptoCore.seal(key: try Self.dek(type, id), plaintext: plain, aad: LeaveCryptoCore.aad(type, id))
      LeaveFiles.ensureParent(of: dstPath)
      try wire.write(to: URL(fileURLWithPath: dstPath), options: [.atomic, .completeFileProtection])
      resolve(["sha256": LeaveCryptoCore.sha256Hex(wire), "sizeBytes": wire.count])
    } catch { reject("crypto", LeaveFiles.fileError(error), error) }
  }

  @objc func decryptFile(_ type: String, id: String, srcPath: String, dstPath: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      let wire = try Data(contentsOf: URL(fileURLWithPath: srcPath))
      let plain = try LeaveCryptoCore.open(key: try Self.dek(type, id), wire: wire, aad: LeaveCryptoCore.aad(type, id))
      LeaveFiles.ensureParent(of: dstPath)
      try plain.write(to: URL(fileURLWithPath: dstPath), options: [.atomic, .completeFileProtection])
      resolve(["sizeBytes": plain.count])
    } catch { reject("crypto", LeaveFiles.fileError(error), error) }
  }

  /// A session grant (contract section 6): a fresh 32-byte session key sealed to the
  /// server's RSA key, plus each requested DEK sealed under that session key. Returns the
  /// JSON body for POST /session/keys and the same JSON as the X-Leave-Grant header value.
  /// Key order in the JSON is sessionId, sealedSessionKey, exp, records (what the server pins).
  @objc func grant(_ sessionId: String, serverSpki: String, exp: NSNumber, records: [[String: String]], resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let spki = LeaveCryptoCore.fromBase64url(serverSpki) else { throw LeaveCryptoCore.Failure.badPublicKey }
      let sessionKey = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      let sealedSessionKey = try LeaveCryptoCore.rsaSeal(serverSpki: spki, sessionKey: sessionKey)
      var items: [String] = []
      for r in records {
        guard let id = r["id"], let type = r["type"] else { continue }
        let sealed = try LeaveCryptoCore.sealDek(sessionKey: sessionKey, sessionId: sessionId, recordId: id, dek: try Self.dek(type, id))
        items.append("{\"id\":\(Self.jsonString(id)),\"type\":\(Self.jsonString(type)),\"sealedDek\":\"\(LeaveCryptoCore.base64url(sealed))\"}")
      }
      let body = "{\"sessionId\":\(Self.jsonString(sessionId)),\"sealedSessionKey\":\"\(LeaveCryptoCore.base64url(sealedSessionKey))\",\"exp\":\(exp.intValue),\"records\":[\(items.joined(separator: ","))]}"
      resolve(["body": body, "header": LeaveCryptoCore.base64url(Data(body.utf8))])
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  /// The same DEK under another record name, for records the contract says share a key
  /// but carry their own AAD: the Markdown upload (`contract:<markdownUploadId>`) and the
  /// extraction (`contractField:<contractId>`) both use the contract's DEK.
  @objc func aliasKey(_ fromType: String, fromId: String, toType: String, toId: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      Self.remember(toType, toId, try Self.dek(fromType, fromId))
      resolve(true)
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  @objc func hasKey(_ type: String, id: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    Self.lock.lock(); let has = Self.deks[Self.key(type, id)] != nil; Self.lock.unlock()
    resolve(has)
  }

  /// The export archive (contract section 5), opened on this phone: every record in
  /// `records/` is decrypted with the key `records/index.json` names for it (imported by
  /// JavaScript from `keys.json` first) under the exact AAD it was sealed with, and written
  /// into a plain zip at `dstPath` beside the archive's readable files. Records whose key
  /// this phone does not hold are listed in `unopened.txt` instead of failing the whole export.
  /// `folder` names the top-level folder inside the zip.
  @objc func openExport(_ zipPath: String, dstPath: String, folder: String, keyTypes: [String: String], resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      let archive = try Data(contentsOf: URL(fileURLWithPath: zipPath))
      guard let indexData = try ZipReader.entry(named: "records/index.json", in: archive),
            let index = try JSONSerialization.jsonObject(with: indexData) as? [String: Any],
            let rows = index["records"] as? [[String: Any]] else {
        throw NSError(domain: "LeaveCrypto", code: 20, userInfo: [NSLocalizedDescriptionKey: "That archive has no record index."])
      }
      var byObject: [String: [String: Any]] = [:]
      for r in rows { if let o = r["object"] as? String { byObject[o] = r } }
      let zip = ZipWriter()
      var opened = 0
      var unopened: [String] = []
      try ZipReader.walk(archive) { name, payload in
        if name.hasSuffix("/") { return true }
        if name == "README.txt" || name == "account.json" || name == "records/index.json" || name == "keys.json" {
          if name != "keys.json" { zip.add("\(folder)/\(name)", try payload()) }
          return true
        }
        guard let row = byObject[name] ?? byObject[String(name.drop(while: { $0 == "/" }))],
              let aad = row["aad"] as? String, let keyId = row["keyRecordId"] as? String, let type = row["type"] as? String else {
          zip.add("\(folder)/\(name)", try payload())
          return true
        }
        let keyType = keyTypes[keyId] ?? type
        guard let dek = try? Self.dek(keyType, keyId) else { unopened.append(name); return true }
        do {
          let plain = try LeaveCryptoCore.open(key: dek, wire: try payload(), aad: Data(aad.utf8))
          zip.add("\(folder)/\(Self.exportName(name, row))", plain)
          opened += 1
        } catch {
          unopened.append(name)
        }
        return true
      }
      if !unopened.isEmpty {
        zip.add("\(folder)/unopened.txt", Data(("These records could not be opened with the key on this phone:\n" + unopened.joined(separator: "\n") + "\n").utf8))
      }
      LeaveFiles.ensureParent(of: dstPath)
      try zip.finish().write(to: URL(fileURLWithPath: dstPath), options: [.atomic, .completeFileProtection])
      resolve(["opened": opened, "unopened": unopened.count])
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  /// `records/contract/<id>.bin` → a name that says what the file is once opened.
  private static func exportName(_ object: String, _ row: [String: Any]) -> String {
    let part = row["part"] as? String
    let contentType = (row["contentType"] as? String) ?? ""
    let ext: String
    switch part {
    case "markdown": ext = "md"
    case "fields": ext = "json"
    case "embedding": ext = "embedding.json"
    default:
      switch contentType {
      case "application/pdf": ext = "pdf"
      case "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ext = "docx"
      case "image/jpeg": ext = "jpg"
      case "image/png": ext = "png"
      case "image/heic": ext = "heic"
      case "text/markdown": ext = "md"
      case "application/json": ext = "json"
      default: ext = object.hasPrefix("records/strand/") || object.hasPrefix("records/thread/") ? "txt" : "bin"
      }
    }
    let base = object.hasSuffix(".bin") ? String(object.dropLast(4)) : object
    return "\(base).\(ext)"
  }

  /// The six digits to compare when a new phone asks for the key (LeaveCryptoCore.compareCode).
  @objc func compareCode(_ key: String, requestId: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    resolve(LeaveCryptoCore.compareCode(key: key, requestId: requestId))
  }

  @objc func forgetKeys(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    Self.lock.lock(); Self.deks.removeAll(); Self.lock.unlock()
    resolve(true)
  }

  @objc func deleteShare(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      try Self.removeShare()
      resolve(true)
    } catch { reject("crypto", error.localizedDescription, error) }
  }

  private static func jsonString(_ s: String) -> String {
    let data = try? JSONSerialization.data(withJSONObject: [s])
    let arr = data.flatMap { String(data: $0, encoding: .utf8) } ?? "[\"\"]"
    return String(arr.dropFirst().dropLast())
  }
}
