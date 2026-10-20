// The iPhone's part in cross-check/cross-check.sh. Compiled with ios/Sources/LeaveCryptoCore/LeaveCryptoCore.swift
// itself (the script removes one import), so what runs here is the iPhone app's own crypto code
// over Apple's CryptoKit, the framework an iPhone runs it on.
//
//   ios-cross make|check|finish <dir>
import CryptoKit
import Foundation

// LeaveCryptoCore's recovery code uses libsodium, which this check does not build. The recovery
// blob is covered on both phones by the shared vectors; this stands in so the file compiles.
struct Sodium {
  struct PwHash {
    enum Alg { case Argon2ID13 }
    func hash(outputLength: Int, passwd: [UInt8], salt: [UInt8], opsLimit: Int, memLimit: Int, alg: Alg) -> [UInt8]? { nil }
  }
  let pwHash = PwHash()
}

let args = CommandLine.arguments
guard args.count == 3 else { fatalError("usage: ios-cross make|check|finish <dir>") }
let phase = args[1], dir = URL(fileURLWithPath: args[2])
let me = "ios", peer = "android"
let C = LeaveCryptoCore.self

func read(_ name: String) throws -> [String: Any] {
  try JSONSerialization.jsonObject(with: Data(contentsOf: dir.appendingPathComponent(name))) as! [String: Any]
}
func write(_ name: String, _ value: [String: Any]) throws {
  try JSONSerialization.data(withJSONObject: value).write(to: dir.appendingPathComponent(name))
}
func b(_ s: Any?) -> Data { C.fromBase64url(s as! String)! }
func u(_ d: Data) -> String { C.base64url(d) }
func same(_ a: Data, _ b2: Data, _ what: String) { if a != b2 { fatalError("ios: \(what) differs") } }
func random(_ n: Int) -> Data { Data((0..<n).map { _ in UInt8.random(in: 0...255) }) }

let common = try read("common.json")
let share = b(common["share"]), accountId = common["accountId"] as! String
let accountKey = try C.accountAgreementKey(share: share, accountId: accountId)

switch phase {
case "make":
  // A record made on the iPhone: a new key, the text sealed under it, the key wrapped to the share.
  let dek = random(32), id = "01J8Z3V4Q6X7R2M9K5T0W1CR10", type = "strand"
  let plaintext = Data("A strand saved on the iPhone, for the Android phone to open.".utf8)
  let device = P256.KeyAgreement.PrivateKey()
  let message = "01J8Z3V4Q6X7R2M9K5T0W1DV10\(accountId)"
  let signature = try C.accountSigningKey(share: share, accountId: accountId).signature(for: Data(message.utf8)).rawRepresentation
  let sessionId = "01J8Z3V4Q6X7R2M9K5T0W1SS10", sessionKey = random(32)
  try write("\(me).1.json", [
    "maker": me,
    "accountPublicKeySpki": u(accountKey.publicKey.derRepresentation),
    "devicePublicKeySpki": u(device.publicKey.derRepresentation),
    "record": ["type": type, "id": id, "plaintext": u(plaintext),
               "wire": u(try C.seal(key: dek, plaintext: plaintext, aad: C.aad(type, id))),
               "shareWrappedDek": u(try C.shareWrap(share: share, recordType: type, recordId: id, dek: dek))],
    "proof": ["message": message, "signatureRaw": u(signature)],
    "grant": ["sessionId": sessionId,
              "sealedSessionKey": u(try C.rsaSeal(serverSpki: b(common["rsaPublicKeySpki"]), sessionKey: sessionKey)),
              "records": [["id": id, "type": type, "sealedDek": u(try C.sealDek(sessionKey: sessionKey, sessionId: sessionId, recordId: id, dek: dek))]]],
  ])
  try write("\(me).private.json", ["deviceScalar": u(device.rawRepresentation)])
  print("iPhone   made a record, a proof and a grant")

case "check":
  let other = try read("\(peer).1.json"), server = try read("server.1.json")
  same(b(other["accountPublicKeySpki"]), accountKey.publicKey.derRepresentation, "the account public key")
  // The Android phone's record: its key unwraps with the share, and the record opens.
  let record = other["record"] as! [String: Any], type = record["type"] as! String, id = record["id"] as! String
  let dek = try C.shareUnwrap(share: share, recordType: type, recordId: id, wire: b(record["shareWrappedDek"]))
  same(try C.open(key: dek, wire: b(record["wire"]), aad: C.aad(type, id)), b(record["plaintext"]), "the Android phone's record")
  let proof = other["proof"] as! [String: Any]
  guard try C.verify(spki: accountKey.publicKey.derRepresentation, message: Data((proof["message"] as! String).utf8), signature: b(proof["signatureRaw"])) else { fatalError("ios: the Android phone's proof does not verify") }
  // The server's record: its key was sealed to the account's public key.
  let made = server["record"] as! [String: Any], sType = made["type"] as! String, sId = made["id"] as! String
  let sDek = try C.hpkeOpen(recipientKey: accountKey, info: made["info"] as! String, wire: b(made["pendingDek"]))
  same(try C.open(key: sDek, wire: b(made["wire"]), aad: C.aad(sType, sId)), b(made["plaintext"]), "the server's record")
  // Approving the Android phone: the share, sealed to that phone's own key.
  try write("\(me).2.json", ["maker": me, "shareForPeerDevice": u(try C.hpkeSeal(recipientSpki: b(other["devicePublicKeySpki"]), info: "leave:v1:device-approve:\(peer)", plaintext: share))])
  print("iPhone   opened the Android phone's record and the server's, verified Android's proof")

case "finish":
  let other = try read("\(peer).2.json"), mine = try read("\(me).private.json")
  let device = try P256.KeyAgreement.PrivateKey(rawRepresentation: b(mine["deviceScalar"]))
  same(try C.hpkeOpen(recipientKey: device, info: "leave:v1:device-approve:\(me)", wire: b(other["shareForPeerDevice"])), share, "the share the Android phone sent")
  print("iPhone   took the share the Android phone wrapped to it")

default:
  fatalError("usage: ios-cross make|check|finish <dir>")
}
