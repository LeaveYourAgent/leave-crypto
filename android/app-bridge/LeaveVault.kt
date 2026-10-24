package com.leaveyouragent.leave.crypto

import android.content.Context
import android.util.Base64
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

/**
 * The one vault and the one set of keys this app process has. JavaScript can start again inside
 * one launch (a reload); the data keys in memory and the signed-in account have to outlive that,
 * as the iPhone's static state does.
 */
object LeaveVault {
  /**
   * The local store's key: 24 random bytes as 32 base64url characters, the iPhone's form. MMKV
   * takes the key as text and AES-256 reads its 32 bytes, so all 192 random bits are used.
   */
  const val STORAGE_KEY_SLOT = "storage-key-v2"

  /** Version code 17 and before: 16 random bytes as 32 hexadecimal characters, read only in part by AES-128. Removed once JavaScript has moved the old stores. */
  const val OLD_STORAGE_KEY_SLOT = "storage-key"

  private var vault: KeyVault? = null
  private var keys: LeaveKeys? = null

  @Synchronized fun vault(context: Context): KeyVault = vault ?: KeyVault(context.applicationContext).also { vault = it }

  @Synchronized
  fun keys(context: Context): LeaveKeys = keys ?: LeaveKeys(vault(context), ShareCarry(PlayBlockStore(context))).also { keys = it }

  /**
   * The key the local store is encrypted with, made on first use from the system's random
   * generator and kept in the vault. The counterpart of the iPhone app's own storage key, which
   * the Keychain holds and JavaScript reads from there.
   */
  fun storageKey(context: Context): String {
    val (key, _) = vault(context).getOrPut(STORAGE_KEY_SLOT) { Base64.encodeToString(LeaveCryptoCore.randomBytes(24), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP).toByteArray(Charsets.US_ASCII) }
    return String(key, Charsets.US_ASCII)
  }

  /** The old key while a store under it may still be on the phone; null once removed. Never made. */
  fun oldStorageKey(context: Context): String? = vault(context).get(OLD_STORAGE_KEY_SLOT)?.let { String(it, Charsets.US_ASCII) }

  fun removeOldStorageKey(context: Context) = vault(context).remove(OLD_STORAGE_KEY_SLOT)
}

/**
 * What JavaScript calls to open its local store on Android (the app's storage code, not in this repository).
 * On iPhone it reads the same key from the Keychain itself; Android has no place that native
 * code and JavaScript's Keychain package both read, so the key is asked for here.
 */
class LeaveVaultModule(context: ReactApplicationContext) : ReactContextBaseJavaModule(context) {
  override fun getName(): String = "LeaveVault"

  @ReactMethod
  fun storageKey(promise: Promise) {
    try {
      promise.resolve(LeaveVault.storageKey(reactApplicationContext))
    } catch (e: Exception) {
      // JavaScript fails closed on this: it shows that the secure storage can't be opened and stores nothing.
      promise.reject("vault", e.message ?: e.javaClass.simpleName, e)
    }
  }

  @ReactMethod
  fun oldStorageKey(promise: Promise) {
    try {
      promise.resolve(LeaveVault.oldStorageKey(reactApplicationContext))
    } catch (e: Exception) {
      promise.reject("vault", e.message ?: e.javaClass.simpleName, e)
    }
  }

  @ReactMethod
  fun removeOldStorageKey(promise: Promise) {
    try {
      LeaveVault.removeOldStorageKey(reactApplicationContext)
      promise.resolve(true)
    } catch (e: Exception) {
      promise.reject("vault", e.message ?: e.javaClass.simpleName, e)
    }
  }
}
