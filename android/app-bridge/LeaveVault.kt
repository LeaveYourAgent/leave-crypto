package com.leaveyouragent.leave.crypto

import android.content.Context
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
  /** The local store's key: 16 random bytes as 32 hexadecimal characters, the iPhone's form. */
  const val STORAGE_KEY_SLOT = "storage-key"

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
    val (key, _) = vault(context).getOrPut(STORAGE_KEY_SLOT) { LeaveCryptoCore.randomBytes(16).joinToString("") { "%02x".format(it) }.toByteArray(Charsets.US_ASCII) }
    return String(key, Charsets.US_ASCII)
  }
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
}
