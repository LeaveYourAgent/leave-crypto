package com.leaveyouragent.leave.crypto

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.UiThreadUtil
import com.leaveyouragent.leave.device.LeaveDeviceKey
import java.io.File

/**
 * What JavaScript calls for the athlete's keys (js/crypto.ts). The Android
 * counterpart of the `@objc` half of ios/app-bridge/LeaveCrypto.swift: the same names, the same
 * arguments, the same answers. Binary values are base64url without padding; big payloads go
 * through file paths, never through the bridge. The share and the data keys never cross into
 * JavaScript.
 */
class LeaveCryptoModule(context: ReactApplicationContext) : ReactContextBaseJavaModule(context) {
  private val core = LeaveCryptoCore
  private val keys = LeaveVault.keys(context)

  override fun getName(): String = "LeaveCrypto"

  /** Runs `work` and answers the promise with what it returns, or with its failure under the iPhone's code. */
  private fun answer(promise: Promise, work: () -> Any?) {
    try {
      promise.resolve(work())
    } catch (e: Exception) {
      promise.reject("crypto", e.message ?: e.javaClass.simpleName, e)
    }
  }

  private fun bytes(text: String, whatFor: String = "Ciphertext is malformed."): ByteArray = core.fromBase64url(text) ?: throw LeaveCryptoCore.Failure(whatFor)

  private fun wrapped(wire: ByteArray) = Arguments.createMap().apply { putString("shareWrappedDek", core.base64url(wire)) }

  /** The Leave account signed in on this phone (null after sign-out). Its id names the share's slot. */
  @ReactMethod fun useAccount(accountId: String?, promise: Promise) = answer(promise) { keys.use(accountId); true }

  /** The iPhone's one-time move from a slot shared by every account. Android never had that slot. */
  @ReactMethod fun adoptLegacyShare(accountId: String, publicKey: String, promise: Promise) = answer(promise) { false }

  @ReactMethod
  fun ensureShare(promise: Promise) = answer(promise) { Arguments.createMap().apply { putBoolean("created", keys.ensureShare().second) } }

  @ReactMethod fun hasShare(promise: Promise) = answer(promise) { keys.hasShare() }

  /** Proof that this phone holds the share: the account key's signature over `message`. Raw r ‖ s, base64url. */
  @ReactMethod
  fun accountProof(accountId: String, message: String, promise: Promise) =
      answer(promise) { core.base64url(core.sign(core.accountScalar(keys.ownShare(), accountId), message.toByteArray(Charsets.UTF_8))) }

  /** The share wrapped to another phone's agreement key (HPKE), for POST /devices/{id}/approve. */
  @ReactMethod
  fun wrapShareTo(recipientSpki: String, info: String, promise: Promise) =
      answer(promise) { core.base64url(core.hpkeSeal(bytes(recipientSpki, "Public key is malformed."), info, keys.ownShare())) }

  /**
   * A new phone takes the share an approving phone wrapped to it: opened with this phone's own
   * agreement key after the person's check, and kept in the vault. It never crosses into
   * JavaScript. It is kept only if it is this account's key (`publicKey`, as the server holds it).
   */
  @ReactMethod
  fun acceptShare(wire: String, info: String, reason: String, accountId: String, publicKey: String, promise: Promise) {
    val sealed = core.fromBase64url(wire) ?: return promise.reject("crypto", "Ciphertext is malformed.")
    UiThreadUtil.runOnUiThread {
      val activity = reactApplicationContext.currentActivity ?: return@runOnUiThread promise.reject("crypto", LeaveDeviceKey.NOT_CONFIRMED)
      LeaveDeviceKey.openWrappedShare(activity, sealed, info, reason) { opened ->
        answer(promise) {
          keys.accept(opened.getOrThrow(), accountId, publicKey)
          true
        }
      }
    }
  }

  @ReactMethod fun accountPublicKey(accountId: String, promise: Promise) = answer(promise) { keys.publicKey(keys.ownShare(), accountId) }

  @ReactMethod fun newRecordKey(type: String, id: String, promise: Promise) = answer(promise) { wrapped(keys.newRecordKey(type, id)) }

  @ReactMethod
  fun importShareWrappedDek(type: String, id: String, wire: String, promise: Promise) =
      answer(promise) { keys.importShareWrappedDek(type, id, bytes(wire)); true }

  @ReactMethod
  fun importPendingDek(type: String, id: String, wire: String, info: String, accountId: String, promise: Promise) =
      answer(promise) { wrapped(keys.importPendingDek(type, id, bytes(wire), info, accountId)) }

  @ReactMethod
  fun wrapDekTo(type: String, id: String, recipientSpki: String, info: String, promise: Promise) =
      answer(promise) { core.base64url(core.hpkeSeal(bytes(recipientSpki, "Public key is malformed."), info, keys.dek(type, id))) }

  @ReactMethod
  fun encrypt(type: String, id: String, plaintext: String, promise: Promise) =
      answer(promise) { core.base64url(core.seal(keys.dek(type, id), bytes(plaintext), core.aad(type, id))) }

  @ReactMethod
  fun decrypt(type: String, id: String, wire: String, promise: Promise) =
      answer(promise) { core.base64url(core.open(keys.dek(type, id), bytes(wire), core.aad(type, id))) }

  /** Whole-file encryption for uploads (≤ 25 MiB, fits memory); returns what POST /uploads needs. */
  @ReactMethod
  fun encryptFile(type: String, id: String, srcPath: String, dstPath: String, promise: Promise) =
      answer(promise) {
        val wire = core.seal(keys.dek(type, id), File(srcPath).readBytes(), core.aad(type, id))
        writeWhole(dstPath, wire)
        Arguments.createMap().apply {
          putString("sha256", core.sha256Hex(wire))
          putInt("sizeBytes", wire.size)
        }
      }

  @ReactMethod
  fun decryptFile(type: String, id: String, srcPath: String, dstPath: String, promise: Promise) =
      answer(promise) {
        val plain = core.open(keys.dek(type, id), File(srcPath).readBytes(), core.aad(type, id))
        writeWhole(dstPath, plain)
        Arguments.createMap().apply { putInt("sizeBytes", plain.size) }
      }

  /** The file appears at `path` whole or not at all. */
  private fun writeWhole(path: String, content: ByteArray) {
    val target = File(path)
    target.parentFile?.mkdirs()
    val temporary = File(path + ".new")
    temporary.writeBytes(content)
    if (!temporary.renameTo(target)) {
      temporary.delete()
      throw java.io.IOException("Could not write the file.")
    }
  }

  /**
   * The export archive opened on this phone (ExportOpener.kt in the app, not in this repository): every record whose key this
   * phone holds is decrypted into a plain zip at `dstPath`; the rest are listed in `unopened.txt`.
   */
  @ReactMethod
  fun openExport(zipPath: String, dstPath: String, folder: String, keyTypes: ReadableMap, promise: Promise) =
      answer(promise) {
        val types = keyTypes.toHashMap().mapValues { it.value.toString() }
        val opened = ExportOpener.open(File(zipPath).readBytes(), folder, types) { type, id -> runCatching { keys.dek(type, id) }.getOrNull() }
        writeWhole(dstPath, opened.zip)
        Arguments.createMap().apply {
          putInt("opened", opened.opened)
          putInt("unopened", opened.unopened)
        }
      }

  /** A session grant: `{ body, header }`, the header being the body as base64url (see LeaveKeys.grant). */
  @ReactMethod
  fun grant(sessionId: String, serverSpki: String, exp: Double, records: ReadableArray, promise: Promise) =
      answer(promise) {
        val wanted =
            (0 until records.size()).mapNotNull { i ->
              val record = records.getMap(i)
              val id = record?.getString("id")
              val type = record?.getString("type")
              if (id != null && type != null) id to type else null
            }
        val body = keys.grant(sessionId, bytes(serverSpki, "Public key is malformed."), exp.toLong(), wanted)
        Arguments.createMap().apply {
          putString("body", body)
          putString("header", core.base64url(body.toByteArray(Charsets.UTF_8)))
        }
      }

  @ReactMethod
  fun aliasKey(fromType: String, fromId: String, toType: String, toId: String, promise: Promise) =
      answer(promise) { keys.aliasKey(fromType, fromId, toType, toId); true }

  @ReactMethod fun hasKey(type: String, id: String, promise: Promise) = answer(promise) { keys.hasKey(type, id) }

  /** The six digits to compare when a new phone asks for the key (LeaveCryptoCore.compareCode). */
  @ReactMethod fun compareCode(key: String, requestId: String, promise: Promise) = answer(promise) { core.compareCode(key, requestId) }

  /** Sign-out: the data keys only; the share stays. */
  @ReactMethod fun forgetKeys(promise: Promise) = answer(promise) { keys.forgetKeys(); true }

  /** Account deletion. */
  @ReactMethod fun deleteShare(promise: Promise) = answer(promise) { keys.removeShare(); true }
}
