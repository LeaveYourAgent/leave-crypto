package com.leaveyouragent.leave.crypto

/**
 * A place outside this phone that can hand a small secret to the person's next phone. One
 * exists: Google's Block Store (PlayBlockStore.kt). Kept behind these four questions so the rule
 * below can be tested on this computer with a stand-in.
 */
interface CarryStore {
  /** Whether what is put here now is encrypted so that only the person's own phones can read it. */
  fun endToEndEncrypted(): Boolean

  fun put(name: String, secret: ByteArray)

  fun get(name: String): ByteArray?

  fun delete(name: String)
}

/**
 * How the athlete's key share follows them to a new Android phone: the counterpart of the
 * iCloud Keychain carrying it between iPhones.
 *
 * Leave decided on 2026-10-09 to carry it in Google's backup, with the condition this class
 * exists to keep:
 *
 * **The share is put in Google's backup only while the phone reports that the backup is
 * end-to-end encrypted, and is taken out of it when the phone stops reporting that.** Google's
 * condition for end-to-end encryption is a screen lock (and Android 9 or later). So on a phone
 * with no screen lock the share is never put there. If a person removes their screen lock, the
 * copy is deleted from Block Store the next time Leave runs on that phone and reads the share
 * (LeaveKeys checks once for each account each time the app runs), and when the account is
 * deleted. Leave can't reach a cloud backup Google made before that; such a backup was itself
 * end-to-end encrypted when it was made.
 *
 * What is put there: one entry per Leave account, 33 bytes (a version byte and the 32-byte
 * share). Its name is a hash, so the entry does not say which Leave account it belongs to.
 */
class ShareCarry(private val store: CarryStore) {
  /** The entry's name for an account: a hash of the account's id, not the id. */
  fun name(accountId: String): String = "share." + LeaveCryptoCore.sha256Hex("leave:v1:carry:$accountId".toByteArray(Charsets.UTF_8)).take(32)

  /**
   * Carries the share if, and only if, the backup is end-to-end encrypted now; otherwise makes
   * sure no copy is there. Returns whether it is carried. A store that fails is "not carried".
   */
  fun keep(accountId: String, share: ByteArray): Boolean {
    if (share.size != 32) return false
    return try {
      if (store.endToEndEncrypted()) {
        store.put(name(accountId), byteArrayOf(VERSION) + share)
        true
      } else {
        store.delete(name(accountId))
        false
      }
    } catch (e: Exception) {
      false
    }
  }

  /** The share that came with the person from their last phone, or null. Anything of another shape is not a share. */
  fun find(accountId: String): ByteArray? =
      try {
        store.get(name(accountId))?.takeIf { it.size == 33 && it[0] == VERSION }?.copyOfRange(1, 33)
      } catch (e: Exception) {
        null
      }

  /** Account deletion: the copy goes too. */
  fun remove(accountId: String) {
    try {
      store.delete(name(accountId))
    } catch (e: Exception) {
      // Nothing to carry on to: the share on this phone is already gone, and the account with it.
    }
  }

  private companion object {
    const val VERSION: Byte = 1
  }
}
