package com.leaveyouragent.leave.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Small secrets kept on this phone: the athlete's key share and the key of the local store, each
 * sealed under a key in the phone's secure hardware. (A copy of the share may also be carried in
 * Google's Block Store under the rule in ShareCarry, and a recovery-code-sealed copy may be on
 * Leave's servers; neither is kept here.) The Android counterpart of the two Keychain items the
 * iPhone app keeps (LeaveCrypto.swift in this repository, and the store's key in the app).
 *
 * Each secret is a file sealed with AES-256-GCM under one key that is made inside the Android
 * Keystore and cannot be taken out of it: the app can ask the Keystore to seal and open, and
 * nothing, the app included, can read the key. The files alone are useless on any other phone.
 *
 * - **Where:** the app's no-backup folder, which Android leaves out of every backup and transfer
 *   whatever else is configured.
 * - **A slot's name is sealed in with it**, so one slot's file cannot be passed off as another's
 *   (one account's share as another account's).
 * - **No fingerprint or screen lock is asked for here.** This is "readable after first unlock",
 *   as on iPhone. What must ask the person each time is the phone's signing key, not this.
 * - **Nothing here is sent to Google's backup.** Whether the share follows the person to a new
 *   phone that way is decided separately, by ShareCarry.
 */
class KeyVault(context: Context, private val keyAlias: String = "leave.vault.v1") {
  /** A slot's file is there and this phone cannot open it. Never treated as "no secret yet". */
  class Unreadable(slot: String, cause: Throwable) : Exception("The secret kept as $slot can't be opened on this phone.", cause)

  private val folder = File(context.noBackupFilesDir, "leave-vault")

  private fun file(slot: String): File = File(folder, LeaveCryptoCore.sha256Hex(slot.toByteArray(Charsets.UTF_8)))

  private fun key(): SecretKey {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (store.getKey(keyAlias, null) as? SecretKey)?.let { return it }
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
      init(
          KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
              .setKeySize(256)
              .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
              .build())
      generateKey()
    }
  }

  /** Null when nothing was ever kept under `slot`. Throws `Unreadable` when something was and can't be opened. */
  @Synchronized
  fun get(slot: String): ByteArray? {
    val file = file(slot)
    if (!file.exists()) return null
    return try {
      val wire = file.readBytes()
      Cipher.getInstance("AES/GCM/NoPadding").run {
        init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, wire, 0, 12))
        updateAAD(slot.toByteArray(Charsets.UTF_8))
        doFinal(wire, 12, wire.size - 12)
      }
    } catch (e: Exception) {
      throw Unreadable(slot, e)
    }
  }

  /** Keeps `secret` under `slot`, replacing what was there. The file appears whole or not at all. */
  @Synchronized
  fun put(slot: String, secret: ByteArray) {
    folder.mkdirs()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key()) // the Keystore draws the nonce itself
    cipher.updateAAD(slot.toByteArray(Charsets.UTF_8))
    val wire = cipher.iv + cipher.doFinal(secret)
    val target = file(slot)
    val temporary = File(folder, target.name + ".new")
    temporary.writeBytes(wire)
    if (!temporary.renameTo(target)) {
      temporary.delete()
      throw java.io.IOException("Could not keep the secret.")
    }
  }

  /** What `slot` holds, made with `make` only if it holds nothing. Second value: whether it was made now. */
  @Synchronized
  fun getOrPut(slot: String, make: () -> ByteArray): Pair<ByteArray, Boolean> {
    get(slot)?.let { return it to false }
    val made = make()
    put(slot, made)
    return made to true
  }

  @Synchronized
  fun remove(slot: String) {
    file(slot).delete()
  }

  /** The exact bytes on disk for a slot, for tests that check what is and isn't in them. */
  fun fileFor(slot: String): File = file(slot)
}
