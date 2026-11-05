import CryptoKit
import Foundation
import React
import Security

/// The Teammate's key on the athlete's and the Teammate's phones: the pin this
/// phone keeps for the Teammate's key, the six digits on a call, and the Teammate's code. The
/// pure parts are LeaveCryptoCore's, held to leave-crypto's teammate-v1 vectors. What is kept
/// here is this device's alone: the newest pin seen, each open run's nonces and the cap. They
/// live in the Keychain, this device only, never synced and never sent.
///
/// JS surface (promises; binary values base64url without padding; refusals reject with their
/// code: pin_record, mac, teammate_unpinned, teammate_removed, sas_field, sas_cap, sas_run,
/// sas_order, sas_open_failed, sas_expired, teammate_store):
///   pinCached()                                        → { record, mac } | null
///   pinAccept(recordJson, mac)                         → "accepted" | "same" | "pin_older" | "pin_record" | "mac"
///   pinMake(teammateAccountId, spkiSha256, compared, how) → { record, mac }   (written by JS, then pinAccept)
///   wrapDekToTeammate(type, id, spki, info)            → HPKE wire, only under the cached pin
///   code(athleteAccountId)                             → "LEAVE-TM1:…"   (the Teammate's own code)
///   checkCode(text, teammateAccountId, spki)           → null | reason
///   sasStatus(athleteAccountId, teammateAccountId)     → { canStart, started, unfinished, nextAt }
///   sasCommit(runId, teammateAccountId, spki)          → commitment   (athlete; counts a run)
///   sasReveal(runId, nT)                               → nA   (athlete; once, and only with nT)
///   sasDigits(runId)                                   → "482913"   (athlete, after the reveal)
///   sasAnswer(runId, athleteAccountId, commitment)     → nT   (Teammate; counts a run)
///   sasCheck(runId, nA)                                → "482913"   (Teammate)
///   sasEnd(runId, finished)                            → true
@objc(LeaveTeammate)
final class LeaveTeammate: NSObject, RCTBridgeModule {
  static func moduleName() -> String! { "LeaveTeammate" }
  static func requiresMainQueueSetup() -> Bool { false }

  enum Failure: String, Error {
    case cap = "sas_cap"
    case run = "sas_run"
    case order = "sas_order"
    case openFailed = "sas_open_failed"
    case expired = "sas_expired"
    /** The Keychain didn't take a write: refused rather than going on as if it had. */
    case store = "teammate_store"
  }

  /// Three runs per athlete–Teammate pair in a rolling 24 hours, on each phone. Started,
  /// answered and aborted runs all count, since a relay that aborts and retries never shows digits.
  static let capRuns = 3
  static let capWindow: Int64 = 24 * 60 * 60

  // MARK: - The store

  /// A variable only so tests use their own.
  static var service = "com.leaveyouragent.leave.teammate"
  private static let lock = NSLock()

  private static func query(_ name: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: name,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
    ]
  }

  static func read(_ name: String) -> [String: Any]? {
    var q = query(name)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
    return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
  }

  /// Updated in place, or added when new. Throws when the Keychain refuses, so the cap and the pin
  /// cache fail closed: never a count dropped, never a cache emptied by a delete that wasn't followed.
  static func write(_ name: String, _ value: [String: Any]) throws {
    let data = try JSONSerialization.data(withJSONObject: value)
    var status = SecItemUpdate(query(name) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
    if status == errSecItemNotFound {
      var add = query(name)
      add[kSecValueData as String] = data
      add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
      status = SecItemAdd(add as CFDictionary, nil)
    }
    guard status == errSecSuccess else { throw Failure.store }
  }

  static func remove(_ name: String) {
    SecItemDelete(query(name) as CFDictionary)
  }

  static func names() -> [String] {
    let q: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
      kSecReturnAttributes as String: true,
      kSecMatchLimit as String: kSecMatchLimitAll,
    ]
    var items: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &items) == errSecSuccess, let list = items as? [[String: Any]] else { return [] }
    return list.compactMap { $0[kSecAttrAccount as String] as? String }
  }

  /// A new install starts with no open run and no count (the plan's answer to a reinstall: a
  /// half-finished run's nA is deleted, never revealed). The pin cache stays: it only ever
  /// refuses older pins, so one left from before can't block a newer one.
  static func wipeRunsAndCaps() {
    lock.lock(); defer { lock.unlock() }
    for name in names() where name.hasPrefix("sas:") || name.hasPrefix("cap:") {
      remove(name)
    }
  }

  // MARK: - The pin

  private static func pinName(_ athleteAccountId: String) -> String { "pin:\(athleteAccountId)" }

  static func cachedPin(athleteAccountId: String) -> LeaveCryptoCore.TeammatePin? {
    guard let saved = read(pinName(athleteAccountId)), let text = saved["record"] as? String, let mac = saved["mac"] as? String,
          let record = LeaveCryptoCore.parseTeammatePinRecord(text) else { return nil }
    return LeaveCryptoCore.TeammatePin(record: record, mac: mac)
  }

  /// A pin the server served: kept when it verifies and is newer than the cache, refused when it
  /// differs and is not newer. The server can't clear or lower the cache.
  static func acceptPin(share: Data, athleteAccountId: String, recordJson: String, mac: String) throws -> LeaveCryptoCore.PinAccept {
    lock.lock(); defer { lock.unlock() }
    let (result, kept) = LeaveCryptoCore.acceptServedTeammatePin(share: share, athleteAccountId: athleteAccountId, cache: cachedPin(athleteAccountId: athleteAccountId), servedRecordJson: recordJson, servedMac: mac)
    if result == .accepted, let kept {
      try write(pinName(athleteAccountId), ["record": LeaveCryptoCore.teammatePinRecordJson(kept.record), "mac": kept.mac])
    }
    return result
  }

  /// A new pin for JS to write. Its `at` is past the newest this phone has seen, so JS first
  /// fetches the server's current pin and passes it through acceptPin; if that fetch fails it
  /// writes nothing. The cache takes the new pin only from acceptPin, once the write went through.
  static func makePin(share: Data, athleteAccountId: String, teammateAccountId: String, spkiSha256: String, compared: Bool, how: String, now: Int64) throws -> LeaveCryptoCore.TeammatePin {
    let seen = cachedPin(athleteAccountId: athleteAccountId)?.record.at
    let record = LeaveCryptoCore.TeammatePinRecord(teammateAccountId: teammateAccountId, spkiSha256: spkiSha256, compared: compared, how: how, at: LeaveCryptoCore.teammatePinWriteAt(nowSeconds: now, newestSeenAt: seen))
    let mac = try LeaveCryptoCore.teammatePinMac(share: share, athleteAccountId: athleteAccountId, record: record)
    return LeaveCryptoCore.TeammatePin(record: record, mac: LeaveCryptoCore.base64url(mac))
  }

  /// The only Teammate wrap: under the cached pin, to the key it names.
  static func wrapToTeammate(share: Data, athleteAccountId: String, spki: Data, info: String, dek: Data) throws -> Data {
    if let refusal = LeaveCryptoCore.teammateWrapRefusal(share: share, athleteAccountId: athleteAccountId, pin: cachedPin(athleteAccountId: athleteAccountId), spki: spki) {
      throw refusal
    }
    return try LeaveCryptoCore.hpkeSeal(recipientSpki: spki, info: info, plaintext: dek)
  }

  // MARK: - Six digits on a call

  private static func runName(_ runId: String) -> String { "sas:\(runId)" }
  private static func capName(_ athlete: String, _ teammate: String) -> String { "cap:\(athlete):\(teammate)" }

  private static func random32() throws -> Data {
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw Failure.run }
    return Data(bytes)
  }

  private static func b64(_ v: Any?) -> Data? { (v as? String).flatMap(LeaveCryptoCore.fromBase64url) }

  /// This pair's runs in the window, oldest first: `[{runId, at, finished}]`.
  private static func capEntries(_ athlete: String, _ teammate: String, now: Int64) -> [[String: Any]] {
    let all = read(capName(athlete, teammate))?["runs"] as? [[String: Any]] ?? []
    return all.filter { (($0["at"] as? NSNumber)?.int64Value ?? 0) > now - capWindow }
  }

  static func status(athlete: String, teammate: String, now: Int64) -> (canStart: Bool, started: Int, unfinished: Int, nextAt: Int64?) {
    lock.lock(); defer { lock.unlock() }
    let runs = capEntries(athlete, teammate, now: now)
    let unfinished = runs.filter { !($0["finished"] as? Bool ?? false) }.count
    let canStart = runs.count < capRuns
    let nextAt = canStart ? nil : ((runs.first?["at"] as? NSNumber)?.int64Value).map { $0 + capWindow }
    return (canStart, runs.count, unfinished, nextAt)
  }

  /// Counts a run for the pair, refused at the cap, and ends any other open run of the pair on
  /// this phone (one open run per pair). Under the lock.
  private static func countRun(runId: String, athlete: String, teammate: String, now: Int64) throws {
    var runs = capEntries(athlete, teammate, now: now)
    // A run id counted before is never used again, open or not.
    guard !runs.contains(where: { $0["runId"] as? String == runId }) else { throw Failure.run }
    guard runs.count < capRuns else { throw Failure.cap }
    for name in names() where name.hasPrefix("sas:") {
      if let run = read(name), run["athlete"] as? String == athlete, run["teammate"] as? String == teammate {
        remove(name)
      }
    }
    runs.append(["runId": runId, "at": NSNumber(value: now), "finished": false])
    try write(capName(athlete, teammate), ["runs": runs])
  }

  /// A run lives 24 hours from its start, as on the server. Past that it is deleted and refused.
  private static func live(_ runId: String, role: String, now: Int64) throws -> [String: Any] {
    guard let run = read(runName(runId)), run["role"] as? String == role else { throw Failure.run }
    guard let at = (run["at"] as? NSNumber)?.int64Value, now - at <= capWindow else {
      remove(runName(runId))
      throw Failure.expired
    }
    return run
  }

  private static func ids(_ runId: String, _ athlete: String, _ teammate: String) -> LeaveCryptoCore.SasIds {
    LeaveCryptoCore.SasIds(runId: runId, athleteAccountId: athlete, teammateAccountId: teammate)
  }

  /// A, on the athlete's tap: commits to the Teammate's key as this phone received it.
  static func commit(runId: String, athlete: String, teammate: String, spki: Data, now: Int64) throws -> Data {
    lock.lock(); defer { lock.unlock() }
    guard LeaveCryptoCore.isUlid(runId), LeaveCryptoCore.isUlid(athlete), LeaveCryptoCore.isUlid(teammate) else { throw LeaveCryptoCore.TeammateRefusal.sasField }
    guard read(runName(runId)) == nil else { throw Failure.run }
    let nA = try random32()
    let c = try LeaveCryptoCore.sasCommit(ids: ids(runId, athlete, teammate), teammateSpki: spki, nA: nA)
    try countRun(runId: runId, athlete: athlete, teammate: teammate, now: now)
    try write(runName(runId), ["role": "A", "athlete": athlete, "teammate": teammate, "spki": LeaveCryptoCore.base64url(spki), "nA": LeaveCryptoCore.base64url(nA), "at": NSNumber(value: now)])
    return c
  }

  /// A, once the Teammate's nonce arrives: keeps it and reveals nA. One nT per run; nA is never
  /// revealed before one.
  static func reveal(runId: String, nT: Data, now: Int64) throws -> Data {
    lock.lock(); defer { lock.unlock() }
    var run = try live(runId, role: "A", now: now)
    guard let nA = b64(run["nA"]) else { throw Failure.run }
    guard run["nT"] == nil else { throw Failure.order }
    guard nT.count == 32 else { throw LeaveCryptoCore.TeammateRefusal.sasField }
    run["nT"] = LeaveCryptoCore.base64url(nT)
    // Kept before nA goes out, so a second nT is refused even after a restart.
    try write(runName(runId), run)
    return nA
  }

  /// A's digits, after the reveal.
  static func digitsA(runId: String, now: Int64) throws -> String {
    lock.lock(); defer { lock.unlock() }
    let run = try live(runId, role: "A", now: now)
    guard let athlete = run["athlete"] as? String, let teammate = run["teammate"] as? String,
          let spki = b64(run["spki"]), let nA = b64(run["nA"]) else { throw Failure.run }
    guard let nT = b64(run["nT"]) else { throw Failure.order }
    return try LeaveCryptoCore.sasDigits(ids: ids(runId, athlete, teammate), teammateSpki: spki, nA: nA, nT: nT).digits
  }

  /// T, only on the Teammate's tap of Show the code: a fresh nT for this run, once.
  static func answer(runId: String, athlete: String, teammate: String, commitment: Data, now: Int64) throws -> Data {
    lock.lock(); defer { lock.unlock() }
    guard LeaveCryptoCore.isUlid(runId), LeaveCryptoCore.isUlid(athlete), LeaveCryptoCore.isUlid(teammate), commitment.count == 32 else { throw LeaveCryptoCore.TeammateRefusal.sasField }
    guard read(runName(runId)) == nil else { throw Failure.run }
    let nT = try random32()
    try countRun(runId: runId, athlete: athlete, teammate: teammate, now: now)
    try write(runName(runId), ["role": "T", "athlete": athlete, "teammate": teammate, "c": LeaveCryptoCore.base64url(commitment), "nT": LeaveCryptoCore.base64url(nT), "at": NSNumber(value: now)])
    return nT
  }

  /// T, once nA is revealed: the digits only if the commitment opens with T's own key. A key
  /// swapped toward the athlete's phone opens nothing, and the run ends with no digits.
  static func check(runId: String, nA: Data, ownSpki: Data, now: Int64) throws -> String {
    lock.lock(); defer { lock.unlock() }
    let run = try live(runId, role: "T", now: now)
    guard let athlete = run["athlete"] as? String, let teammate = run["teammate"] as? String,
          let c = b64(run["c"]), let nT = b64(run["nT"]) else { throw Failure.run }
    guard nA.count == 32 else { throw LeaveCryptoCore.TeammateRefusal.sasField }
    guard try LeaveCryptoCore.sasOpens(ids: ids(runId, athlete, teammate), ownSpki: ownSpki, nA: nA, commitment: c) else {
      remove(runName(runId))
      throw Failure.openFailed
    }
    return try LeaveCryptoCore.sasDigits(ids: ids(runId, athlete, teammate), teammateSpki: ownSpki, nA: nA, nT: nT).digits
  }

  /// The run is over: its nonces go. `finished` (the athlete's Codes match, or the Teammate's
  /// digits shown and answered) keeps it out of the "did not finish" line; it still counts.
  static func end(runId: String, finished: Bool) {
    lock.lock(); defer { lock.unlock() }
    if let run = read(runName(runId)), let athlete = run["athlete"] as? String, let teammate = run["teammate"] as? String, finished {
      let name = capName(athlete, teammate)
      let runs = (read(name)?["runs"] as? [[String: Any]] ?? []).map { entry -> [String: Any] in
        var e = entry
        if e["runId"] as? String == runId { e["finished"] = true }
        return e
      }
      // Only the "did not finish" line depends on this; the run still counts toward the cap.
      try? write(name, ["runs": runs])
    }
    remove(runName(runId))
  }

  // MARK: - JS

  private static func now() -> Int64 { Int64(Date().timeIntervalSince1970) }

  private func fail(_ reject: RCTPromiseRejectBlock, _ error: Error) {
    switch error {
    case let f as Failure: reject(f.rawValue, f.rawValue, error)
    case let r as LeaveCryptoCore.TeammateRefusal: reject(r.rawValue, r.rawValue, error)
    default: reject("teammate", error.localizedDescription, error)
    }
  }

  @objc func pinCached(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let pin = Self.cachedPin(athleteAccountId: try LeaveCrypto.currentAccount()) else { resolve(NSNull()); return }
      resolve(["record": LeaveCryptoCore.teammatePinRecordJson(pin.record), "mac": pin.mac])
    } catch { fail(reject, error) }
  }

  @objc func pinAccept(_ recordJson: String, mac: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      resolve(try Self.acceptPin(share: try LeaveCrypto.ownShare(), athleteAccountId: try LeaveCrypto.currentAccount(), recordJson: recordJson, mac: mac).rawValue)
    } catch { fail(reject, error) }
  }

  @objc func pinMake(_ teammateAccountId: String, spkiSha256: String, compared: Bool, how: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      let pin = try Self.makePin(share: try LeaveCrypto.ownShare(), athleteAccountId: try LeaveCrypto.currentAccount(), teammateAccountId: teammateAccountId, spkiSha256: spkiSha256, compared: compared, how: how, now: Self.now())
      resolve(["record": LeaveCryptoCore.teammatePinRecordJson(pin.record), "mac": pin.mac])
    } catch { fail(reject, error) }
  }

  @objc func wrapDekToTeammate(_ type: String, id: String, spki: String, info: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let key = LeaveCryptoCore.fromBase64url(spki) else { throw LeaveCryptoCore.Failure.badPublicKey }
      let wire = try Self.wrapToTeammate(share: try LeaveCrypto.ownShare(), athleteAccountId: try LeaveCrypto.currentAccount(), spki: key, info: info, dek: try LeaveCrypto.recordKey(type, id))
      resolve(LeaveCryptoCore.base64url(wire))
    } catch { fail(reject, error) }
  }

  @objc func code(_ athleteAccountId: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      let me = try LeaveCrypto.currentAccount()
      let spki = try LeaveCryptoCore.accountAgreementKey(share: try LeaveCrypto.ownShare(), accountId: me).publicKey.derRepresentation
      guard let text = LeaveCryptoCore.teammateCode(athleteAccountId: athleteAccountId, teammateAccountId: me, ownSpki: spki) else { throw LeaveCryptoCore.TeammateRefusal.sasField }
      resolve(text)
    } catch { fail(reject, error) }
  }

  @objc func checkCode(_ text: String, teammateAccountId: String, spki: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let key = LeaveCryptoCore.fromBase64url(spki) else { throw LeaveCryptoCore.Failure.badPublicKey }
      resolve(LeaveCryptoCore.checkTeammateCode(text, myAccountId: try LeaveCrypto.currentAccount(), teammateAccountId: teammateAccountId, receivedSpki: key) ?? NSNull())
    } catch { fail(reject, error) }
  }

  @objc func sasStatus(_ athleteAccountId: String, teammateAccountId: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    let s = Self.status(athlete: athleteAccountId, teammate: teammateAccountId, now: Self.now())
    resolve(["canStart": s.canStart, "started": s.started, "unfinished": s.unfinished, "nextAt": s.nextAt.map { NSNumber(value: $0) } ?? NSNull()])
  }

  @objc func sasCommit(_ runId: String, teammateAccountId: String, spki: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let key = LeaveCryptoCore.fromBase64url(spki) else { throw LeaveCryptoCore.Failure.badPublicKey }
      resolve(LeaveCryptoCore.base64url(try Self.commit(runId: runId, athlete: try LeaveCrypto.currentAccount(), teammate: teammateAccountId, spki: key, now: Self.now())))
    } catch { fail(reject, error) }
  }

  @objc func sasReveal(_ runId: String, nT: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let n = LeaveCryptoCore.fromBase64url(nT) else { throw LeaveCryptoCore.TeammateRefusal.sasField }
      resolve(LeaveCryptoCore.base64url(try Self.reveal(runId: runId, nT: n, now: Self.now())))
    } catch { fail(reject, error) }
  }

  @objc func sasDigits(_ runId: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do { resolve(try Self.digitsA(runId: runId, now: Self.now())) } catch { fail(reject, error) }
  }

  @objc func sasAnswer(_ runId: String, athleteAccountId: String, commitment: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let c = LeaveCryptoCore.fromBase64url(commitment) else { throw LeaveCryptoCore.TeammateRefusal.sasField }
      resolve(LeaveCryptoCore.base64url(try Self.answer(runId: runId, athlete: athleteAccountId, teammate: try LeaveCrypto.currentAccount(), commitment: c, now: Self.now())))
    } catch { fail(reject, error) }
  }

  @objc func sasCheck(_ runId: String, nA: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    do {
      guard let n = LeaveCryptoCore.fromBase64url(nA) else { throw LeaveCryptoCore.TeammateRefusal.sasField }
      let me = try LeaveCrypto.currentAccount()
      let own = try LeaveCryptoCore.accountAgreementKey(share: try LeaveCrypto.ownShare(), accountId: me).publicKey.derRepresentation
      resolve(try Self.check(runId: runId, nA: n, ownSpki: own, now: Self.now()))
    } catch { fail(reject, error) }
  }

  @objc func sasEnd(_ runId: String, finished: Bool, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    Self.end(runId: runId, finished: finished)
    resolve(true)
  }
}
