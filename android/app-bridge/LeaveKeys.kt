package com.leaveyouragent.leave.crypto

/**
 * The athlete's keys, held natively so JavaScript never sees the share or a data key. The
 * Android counterpart of the static half of ios/app-bridge/LeaveCrypto.swift; LeaveCryptoModule is
 * the thin layer JavaScript calls.
 *
 * - The athlete share (32 random bytes) is kept in the vault, one slot per Leave account, and
 *   follows the athlete to their next phone through `carry` when the rule in ShareCarry allows.
 * - Data keys (DEKs) are made here, kept in memory for the session, and leave the process only
 *   wrapped: to the share (share wrap), to a public key (HPKE) or to the server's session key
 *   (a grant).
 *
 * The messages below are the iPhone's, word for word: JavaScript shows some of them.
 */
class LeaveKeys(
    private val vault: KeyVault,
    private val carry: ShareCarry? = null,
    /** Runs the upkeep of the carried copy; it waits on Google Play services, so never inline. */
    private val later: (() -> Unit) -> Unit = { work -> Thread(work, "leave-share-carry").start() },
) {
  class Refused(message: String) : Exception(message)

  /** Accounts whose carried copy has been brought up to date since the app started. */
  private val settled = HashSet<String>()

  private val deks = HashMap<String, ByteArray>()
  /** The Leave account whose key this phone is working with. Its id names the share's slot. */
  private var account: String? = null

  private fun name(type: String, id: String) = "$type:$id"

  private fun slot(accountId: String) = "share:$accountId"

  @Synchronized
  fun dek(type: String, id: String): ByteArray = deks[name(type, id)] ?: throw Refused("No key for $type $id in this session.")

  @Synchronized
  fun remember(type: String, id: String, dek: ByteArray) {
    deks[name(type, id)] = dek
  }

  @Synchronized fun hasKey(type: String, id: String): Boolean = deks.containsKey(name(type, id))

  @Synchronized fun forgetKeys() = deks.clear()

  // Share

  /**
   * One slot per Leave account, as on iPhone since build 45: nothing here ever deletes
   * or replaces another account's share. Changing account drops every data key in memory.
   */
  @Synchronized
  fun use(accountId: String?) {
    if (account != accountId) {
      account = accountId
      deks.clear()
    }
  }

  @Synchronized
  private fun current(): String = account?.takeIf { it.isNotEmpty() } ?: throw Refused("No Leave account is signed in on this phone.")

  /**
   * The signed-in account's own share, and nothing else. It is created only by `ensureShare`
   * (the first phone on an account); everything else fails rather than mint a second one.
   *
   * On a phone that holds none, the share that came with the person from their last phone is
   * taken in, if there is one.
   */
  fun ownShare(): ByteArray = held(current()) ?: throw Refused("This phone does not hold your key yet.")

  private fun held(accountId: String): ByteArray? {
    vault.get(slot(accountId))?.let { share ->
      settle(accountId, share)
      return share
    }
    val carried = carry?.find(accountId) ?: return null
    vault.put(slot(accountId), carried)
    settle(accountId, carried)
    return carried
  }

  /**
   * Brings the carried copy in line with the rule, once for each account each time the app
   * runs: there while the backup is end-to-end encrypted, gone when it is not (a screen lock
   * set or removed since the last run).
   */
  private fun settle(accountId: String, share: ByteArray, again: Boolean = false) {
    val carry = carry ?: return
    synchronized(settled) { if (!settled.add(accountId) && !again) return }
    later { carry.keep(accountId, share) }
  }

  fun hasShare(): Boolean = try { ownShare(); true } catch (e: Refused) { false }

  /**
   * Creates the account's share on first use. Never overwrites one, and never makes a second
   * beside one the person's last phone carried here. Second value: whether it was made now.
   */
  fun ensureShare(): Pair<ByteArray, Boolean> {
    val accountId = current()
    held(accountId)?.let { return it to false }
    val (share, made) = vault.getOrPut(slot(accountId)) { LeaveCryptoCore.randomBytes(32) }
    settle(accountId, share, again = true)
    return share to made
  }

  /** The account key's public half, as the server holds it (SPKI DER, base64url). */
  fun publicKey(share: ByteArray, accountId: String): String = LeaveCryptoCore.base64url(LeaveCryptoCore.accountPublicKeySpki(share, accountId))

  /**
   * The share an approving phone or a recovery code gave, kept only if it is this account's key
   * (`expected`, as the server holds it). Only this account's slot is replaced.
   */
  fun accept(share: ByteArray, accountId: String, expected: String) {
    if (share.size != 32) throw LeaveCryptoCore.Failure("Ciphertext is malformed.")
    if (accountId.isEmpty() || publicKey(share, accountId) != expected) {
      throw Refused("The key that arrived is not this account's key. Nothing was changed.")
    }
    vault.put(slot(accountId), share)
    forgetKeys()
    settle(accountId, share, again = true)
  }

  /** Account deletion: this account's slot only, and its carried copy. */
  fun removeShare() {
    val accountId = current()
    vault.remove(slot(accountId))
    forgetKeys()
    carry?.let { carry ->
      synchronized(settled) { settled.remove(accountId) }
      later { carry.remove(accountId) }
    }
  }

  // Records

  /** A new record's data key, kept for the session, and its wrap to the share for the server to hold. */
  fun newRecordKey(type: String, id: String): ByteArray {
    val share = ownShare()
    val dek = LeaveCryptoCore.randomBytes(32)
    remember(type, id, dek)
    return LeaveCryptoCore.shareWrap(share, type, id, dek)
  }

  fun importShareWrappedDek(type: String, id: String, wire: ByteArray) {
    remember(type, id, LeaveCryptoCore.shareUnwrap(ownShare(), type, id, wire))
  }

  /**
   * A record the server created: its DEK arrives HPKE-wrapped to the account key. Unwrap it,
   * keep it, and hand back the share wrap the app then stores with PUT /records/keys.
   */
  fun importPendingDek(type: String, id: String, wire: ByteArray, info: String, accountId: String): ByteArray {
    val share = ownShare()
    val dek = LeaveCryptoCore.hpkeOpen(LeaveCryptoCore.accountScalar(share, accountId), info, wire)
    remember(type, id, dek)
    return LeaveCryptoCore.shareWrap(share, type, id, dek)
  }

  /** The same DEK under another record name, for records the contract says share a key. */
  fun aliasKey(fromType: String, fromId: String, toType: String, toId: String) = remember(toType, toId, dek(fromType, fromId))

  /**
   * A session grant (contract section 6): a fresh 32-byte session key sealed to the server's RSA
   * key, plus each requested DEK sealed under that session key. Returns the JSON body for
   * POST /session/keys; the X-Leave-Grant header is the same text as base64url. Key order in the
   * JSON is sessionId, sealedSessionKey, exp, records (what the server pins).
   */
  fun grant(sessionId: String, serverSpki: ByteArray, exp: Long, records: List<Pair<String, String>>): String {
    val core = LeaveCryptoCore
    val sessionKey = core.randomBytes(32)
    val sealedSessionKey = core.rsaSeal(serverSpki, sessionKey)
    val items =
        records.joinToString(",") { (id, type) ->
          val sealed = core.sealDek(sessionKey, sessionId, id, dek(type, id))
          "{\"id\":${core.jsonString(id)},\"type\":${core.jsonString(type)},\"sealedDek\":\"${core.base64url(sealed)}\"}"
        }
    return "{\"sessionId\":${core.jsonString(sessionId)},\"sealedSessionKey\":\"${core.base64url(sealedSessionKey)}\",\"exp\":$exp,\"records\":[$items]}"
  }
}
