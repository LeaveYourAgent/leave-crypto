package com.leaveyouragent.leave.crypto

import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The Android phone's part in cross-check/cross-check.sh: the same athlete on an iPhone and
 * an Android phone, with the server between them. What one seals the other opens, in both
 * directions, with the iPhone app's own code on Apple's CryptoKit on the other side.
 *
 * Skipped unless the script runs it (it passes the folder and the phase).
 */
class LeaveCryptoCrossCheck {
  private val core = LeaveCryptoCore
  private val dir = System.getProperty("leave.cross.dir").orEmpty()
  private val me = "android"
  private val peer = "ios"

  private fun read(name: String) = JSONObject(File(dir, name).readText())
  private fun write(name: String, value: JSONObject) = File(dir, name).writeText(value.toString())
  private fun JSONObject.bytes(name: String) = core.fromBase64url(getString(name))!!
  private fun u(bytes: ByteArray) = core.base64url(bytes)
  private fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)

  @Test
  fun crossCheck() {
    assumeTrue("run by cross-check/cross-check.sh", dir.isNotEmpty())
    val common = read("common.json")
    val share = common.bytes("share")
    val accountId = common.getString("accountId")
    val scalar = core.accountScalar(share, accountId)
    val accountKey = core.accountPublicKeySpki(share, accountId)

    when (System.getProperty("leave.cross.phase")) {
      "make" -> {
        // A record made on the Android phone: a new key, the text sealed under it, the key wrapped to the share.
        val dek = core.randomBytes(32)
        val id = "01J8Z3V4Q6X7R2M9K5T0W1CRAN"
        val type = "strand"
        val plaintext = utf8("A strand saved on the Android phone, for the iPhone to open.")
        var deviceScalar = core.randomBytes(32)
        while (!core.scalarInRange(deviceScalar)) deviceScalar = core.randomBytes(32)
        val message = "01J8Z3V4Q6X7R2M9K5T0W1DVAN$accountId"
        val sessionId = "01J8Z3V4Q6X7R2M9K5T0W1SSAN"
        val sessionKey = core.randomBytes(32)
        write(
            "$me.1.json",
            JSONObject()
                .put("maker", me)
                .put("accountPublicKeySpki", u(accountKey))
                .put("devicePublicKeySpki", u(core.spkiOfRaw(core.publicKeyRaw(deviceScalar))))
                .put("record", JSONObject().put("type", type).put("id", id).put("plaintext", u(plaintext))
                    .put("wire", u(core.seal(dek, plaintext, core.aad(type, id))))
                    .put("shareWrappedDek", u(core.shareWrap(share, type, id, dek))))
                .put("proof", JSONObject().put("message", message).put("signatureRaw", u(core.sign(scalar, utf8(message)))))
                .put("grant", JSONObject().put("sessionId", sessionId)
                    .put("sealedSessionKey", u(core.rsaSeal(common.bytes("rsaPublicKeySpki"), sessionKey)))
                    .put("records", JSONArray().put(JSONObject().put("id", id).put("type", type).put("sealedDek", u(core.sealDek(sessionKey, sessionId, id, dek)))))))
        write("$me.private.json", JSONObject().put("deviceScalar", u(deviceScalar)))
        println("Android  made a record, a proof and a grant")
      }
      "check" -> {
        val other = read("$peer.1.json")
        assertArrayEquals("the account public key", accountKey, other.bytes("accountPublicKeySpki"))
        // The iPhone's record: its key unwraps with the share, and the record opens.
        val record = other.getJSONObject("record")
        val type = record.getString("type")
        val id = record.getString("id")
        val dek = core.shareUnwrap(share, type, id, record.bytes("shareWrappedDek"))
        assertArrayEquals("the iPhone's record", record.bytes("plaintext"), core.open(dek, record.bytes("wire"), core.aad(type, id)))
        val proof = other.getJSONObject("proof")
        assertTrue("the iPhone's proof", core.verify(accountKey, utf8(proof.getString("message")), proof.bytes("signatureRaw")))
        // The server's record: its key was sealed to the account's public key.
        val made = read("server.1.json").getJSONObject("record")
        val serversDek = core.hpkeOpen(scalar, made.getString("info"), made.bytes("pendingDek"))
        assertArrayEquals("the server's record", made.bytes("plaintext"), core.open(serversDek, made.bytes("wire"), core.aad(made.getString("type"), made.getString("id"))))
        // Approving the iPhone: the share, sealed to that phone's own key.
        write("$me.2.json", JSONObject().put("maker", me).put("shareForPeerDevice", u(core.hpkeSeal(other.bytes("devicePublicKeySpki"), "leave:v1:device-approve:$peer", share))))
        println("Android  opened the iPhone's record and the server's, verified the iPhone's proof")
      }
      "finish" -> {
        val deviceScalar = read("$me.private.json").bytes("deviceScalar")
        val sent = read("$peer.2.json").bytes("shareForPeerDevice")
        assertArrayEquals("the share the iPhone sent", share, core.hpkeOpen(deviceScalar, "leave:v1:device-approve:$me", sent))
        println("Android  took the share the iPhone wrapped to it")
      }
      else -> error("leave.cross.phase must be make, check or finish")
    }
  }
}
