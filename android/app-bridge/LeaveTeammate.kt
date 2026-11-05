package com.leaveyouragent.leave.crypto

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import org.json.JSONArray
import org.json.JSONObject

/**
 * The Teammate's key on the athlete's and the Teammate's phones, the Android
 * counterpart of the iPhone app's LeaveTeammate.swift: the pin this phone keeps for the Teammate's key,
 * the six digits on a call, and the Teammate's code. The pure parts are LeaveCryptoCore's, held to
 * leave-crypto's teammate-v1 vectors. What is kept here is this device's alone, in the vault: the
 * newest pin seen (one slot per athlete account), and every open run with the cap (one slot). An
 * uninstall removes the vault with the rest of the app's data.
 *
 * `get`, `put` and `remove` are the vault's, so the rules run in JVM tests over a map. The vault's
 * `put` throws when it can't keep a secret, so a count or a pin is never lost silently: the cap and
 * the pin cache fail closed.
 */
class TeammateState(
    private val get: (String) -> ByteArray?,
    private val put: (String, ByteArray) -> Unit,
    private val remove: (String) -> Unit,
) {
  class Failure(val code: String) : Exception(code)

  companion object {
    /** Three runs per athlete–Teammate pair in a rolling 24 hours, started, answered and aborted. */
    const val CAP_RUNS = 3
    const val CAP_WINDOW = 24L * 60 * 60
    const val SAS_SLOT = "teammate:sas"
  }

  private val core = LeaveCryptoCore

  private fun pinSlot(athlete: String) = "teammate:pin:$athlete"

  private fun json(slot: String): JSONObject? = get(slot)?.let { JSONObject(String(it, Charsets.UTF_8)) }

  private fun keep(slot: String, value: JSONObject) = put(slot, value.toString().toByteArray(Charsets.UTF_8))

  // The pin

  @Synchronized
  fun cachedPin(athlete: String): LeaveCryptoCore.TeammatePin? {
    val saved = json(pinSlot(athlete)) ?: return null
    val record = core.parseTeammatePinRecord(saved.optString("record")) ?: return null
    return LeaveCryptoCore.TeammatePin(record, saved.optString("mac"))
  }

  /** A served pin: kept when it verifies and is newer than the cache; the server can't clear or lower it. */
  @Synchronized
  fun acceptPin(share: ByteArray, athlete: String, recordJson: String, mac: String): String {
    val (result, kept) = core.acceptServedTeammatePin(share, athlete, cachedPin(athlete), recordJson, mac)
    if (result == "accepted" && kept != null) {
      keep(pinSlot(athlete), JSONObject().put("record", core.teammatePinRecordJson(kept.record)).put("mac", kept.mac))
    }
    return result
  }

  /** A new pin for JS to write, past the newest seen; the cache takes it only through acceptPin. */
  @Synchronized
  fun makePin(share: ByteArray, athlete: String, teammate: String, spkiSha256: String, compared: Boolean, how: String, now: Long): LeaveCryptoCore.TeammatePin {
    val record = LeaveCryptoCore.TeammatePinRecord(teammate, spkiSha256, compared, how, core.teammatePinWriteAt(now, cachedPin(athlete)?.record?.at))
    return LeaveCryptoCore.TeammatePin(record, core.base64url(core.teammatePinMac(share, athlete, record)))
  }

  /** The only Teammate wrap: under the cached pin, to the key it names. */
  fun wrapToTeammate(share: ByteArray, athlete: String, spki: ByteArray, info: String, dek: ByteArray): ByteArray {
    core.teammateWrapRefusal(share, athlete, cachedPin(athlete), spki)?.let { throw LeaveCryptoCore.TeammateRefusal(it) }
    return core.hpkeSeal(spki, info, dek)
  }

  // Six digits on a call

  private fun sas(): JSONObject = json(SAS_SLOT) ?: JSONObject().put("runs", JSONObject()).put("caps", JSONObject())

  private fun capKey(athlete: String, teammate: String) = "$athlete:$teammate"

  /** This pair's runs in the window, oldest first. */
  private fun capEntries(state: JSONObject, athlete: String, teammate: String, now: Long): MutableList<JSONObject> {
    val all = state.getJSONObject("caps").optJSONArray(capKey(athlete, teammate)) ?: JSONArray()
    return (0 until all.length()).map { all.getJSONObject(it) }.filter { it.getLong("at") > now - CAP_WINDOW }.toMutableList()
  }

  data class Status(val canStart: Boolean, val started: Int, val unfinished: Int, val nextAt: Long?)

  @Synchronized
  fun status(athlete: String, teammate: String, now: Long): Status {
    val runs = capEntries(sas(), athlete, teammate, now)
    val canStart = runs.size < CAP_RUNS
    return Status(canStart, runs.size, runs.count { !it.optBoolean("finished") }, if (canStart) null else runs.first().getLong("at") + CAP_WINDOW)
  }

  /** Counts a run, refused at the cap, and ends the pair's other open run on this phone. */
  private fun countRun(state: JSONObject, runId: String, athlete: String, teammate: String, now: Long) {
    val runs = capEntries(state, athlete, teammate, now)
    // A run id counted before is never used again, open or not.
    if (runs.any { it.optString("runId") == runId }) throw Failure("sas_run")
    if (runs.size >= CAP_RUNS) throw Failure("sas_cap")
    val open = state.getJSONObject("runs")
    open.keys().asSequence().toList().forEach { id ->
      val r = open.getJSONObject(id)
      if (r.getString("athlete") == athlete && r.getString("teammate") == teammate) open.remove(id)
    }
    runs.add(JSONObject().put("runId", runId).put("at", now).put("finished", false))
    state.getJSONObject("caps").put(capKey(athlete, teammate), JSONArray(runs))
  }

  /** A run lives 24 hours from its start, as on the server. Past that it is deleted and refused. */
  private fun live(state: JSONObject, runId: String, role: String, now: Long): JSONObject {
    val run = state.getJSONObject("runs").optJSONObject(runId)?.takeIf { it.getString("role") == role } ?: throw Failure("sas_run")
    if (now - run.optLong("at", Long.MIN_VALUE / 2) > CAP_WINDOW) {
      state.getJSONObject("runs").remove(runId)
      keep(SAS_SLOT, state)
      throw Failure("sas_expired")
    }
    return run
  }

  private fun ids(runId: String, athlete: String, teammate: String) = LeaveCryptoCore.SasIds(runId, athlete, teammate)

  private fun ulids(vararg s: String) {
    if (!s.all { core.isUlid(it) }) throw LeaveCryptoCore.TeammateRefusal("sas_field")
  }

  private fun bytesOf(r: JSONObject, name: String): ByteArray? = r.optString(name).takeIf { it.isNotEmpty() }?.let { core.fromBase64url(it) }

  /** A, on the athlete's tap: commits to the Teammate's key as this phone received it. */
  @Synchronized
  fun commit(runId: String, athlete: String, teammate: String, spki: ByteArray, now: Long): ByteArray {
    ulids(runId, athlete, teammate)
    val state = sas()
    if (state.getJSONObject("runs").has(runId)) throw Failure("sas_run")
    val nA = core.randomBytes(32)
    val c = core.sasCommit(ids(runId, athlete, teammate), spki, nA)
    countRun(state, runId, athlete, teammate, now)
    state.getJSONObject("runs").put(runId, JSONObject().put("role", "A").put("athlete", athlete).put("teammate", teammate).put("spki", core.base64url(spki)).put("nA", core.base64url(nA)).put("at", now))
    keep(SAS_SLOT, state)
    return c
  }

  /** A, once the Teammate's nonce arrives: keeps it and reveals nA, once, never before an nT. */
  @Synchronized
  fun reveal(runId: String, nT: ByteArray, now: Long): ByteArray {
    val state = sas()
    val run = live(state, runId, "A", now)
    val nA = bytesOf(run, "nA") ?: throw Failure("sas_run")
    if (run.has("nT")) throw Failure("sas_order")
    if (nT.size != 32) throw LeaveCryptoCore.TeammateRefusal("sas_field")
    run.put("nT", core.base64url(nT))
    keep(SAS_SLOT, state)
    return nA
  }

  /** A's digits, after the reveal. */
  @Synchronized
  fun digitsA(runId: String, now: Long): String {
    val run = live(sas(), runId, "A", now)
    val nT = bytesOf(run, "nT") ?: throw Failure("sas_order")
    return core.sasDigits(ids(runId, run.getString("athlete"), run.getString("teammate")), bytesOf(run, "spki")!!, bytesOf(run, "nA")!!, nT).second
  }

  /** T, only on the Teammate's tap of Show the code: a fresh nT for this run, once. */
  @Synchronized
  fun answer(runId: String, athlete: String, teammate: String, commitment: ByteArray, now: Long): ByteArray {
    ulids(runId, athlete, teammate)
    if (commitment.size != 32) throw LeaveCryptoCore.TeammateRefusal("sas_field")
    val state = sas()
    if (state.getJSONObject("runs").has(runId)) throw Failure("sas_run")
    val nT = core.randomBytes(32)
    countRun(state, runId, athlete, teammate, now)
    state.getJSONObject("runs").put(runId, JSONObject().put("role", "T").put("athlete", athlete).put("teammate", teammate).put("c", core.base64url(commitment)).put("nT", core.base64url(nT)).put("at", now))
    keep(SAS_SLOT, state)
    return nT
  }

  /** T, once nA is revealed: digits only if the commitment opens with T's own key; else the run ends. */
  @Synchronized
  fun check(runId: String, nA: ByteArray, ownSpki: ByteArray, now: Long): String {
    val state = sas()
    val run = live(state, runId, "T", now)
    if (nA.size != 32) throw LeaveCryptoCore.TeammateRefusal("sas_field")
    val ids = ids(runId, run.getString("athlete"), run.getString("teammate"))
    if (!core.sasOpens(ids, ownSpki, nA, bytesOf(run, "c")!!)) {
      state.getJSONObject("runs").remove(runId)
      keep(SAS_SLOT, state)
      throw Failure("sas_open_failed")
    }
    return core.sasDigits(ids, ownSpki, nA, bytesOf(run, "nT")!!).second
  }

  /** The run is over: its nonces go. `finished` keeps it out of the "did not finish" line; it still counts. */
  @Synchronized
  fun end(runId: String, finished: Boolean) {
    val state = sas()
    val run = state.getJSONObject("runs").optJSONObject(runId) ?: return
    if (finished) {
      val entries = state.getJSONObject("caps").optJSONArray(capKey(run.getString("athlete"), run.getString("teammate"))) ?: JSONArray()
      for (i in 0 until entries.length()) {
        if (entries.getJSONObject(i).optString("runId") == runId) entries.getJSONObject(i).put("finished", true)
      }
    }
    state.getJSONObject("runs").remove(runId)
    keep(SAS_SLOT, state)
  }

  /** Every open run and the count go; the pins stay. */
  @Synchronized fun wipeRunsAndCaps() = remove(SAS_SLOT)
}

/**
 * What JavaScript calls (src/data/api/teammate.ts): the same names, arguments and answers as the
 * iPhone's LeaveTeammate. Refusals reject with their code.
 */
class LeaveTeammateModule(context: ReactApplicationContext) : ReactContextBaseJavaModule(context) {
  private val core = LeaveCryptoCore
  private val keys = LeaveVault.keys(context)
  private val vault = LeaveVault.vault(context)
  private val state = TeammateState(vault::get, vault::put, vault::remove)

  override fun getName(): String = "LeaveTeammate"

  private fun answer(promise: Promise, work: () -> Any?) {
    try {
      promise.resolve(work())
    } catch (e: TeammateState.Failure) {
      promise.reject(e.code, e.code, e)
    } catch (e: LeaveCryptoCore.TeammateRefusal) {
      promise.reject(e.reason, e.reason, e)
    } catch (e: Exception) {
      promise.reject("teammate", e.message ?: e.javaClass.simpleName, e)
    }
  }

  private fun bytes(text: String, code: String = "sas_field"): ByteArray = core.fromBase64url(text) ?: throw LeaveCryptoCore.TeammateRefusal(code)

  private fun now(): Long = System.currentTimeMillis() / 1000

  private fun pinMap(pin: LeaveCryptoCore.TeammatePin) = Arguments.createMap().apply {
    putString("record", core.teammatePinRecordJson(pin.record))
    putString("mac", pin.mac)
  }

  private fun ownSpki(): ByteArray = core.accountPublicKeySpki(keys.ownShare(), keys.currentAccount())

  @ReactMethod fun pinCached(promise: Promise) = answer(promise) { state.cachedPin(keys.currentAccount())?.let(::pinMap) }

  @ReactMethod
  fun pinAccept(recordJson: String, mac: String, promise: Promise) = answer(promise) { state.acceptPin(keys.ownShare(), keys.currentAccount(), recordJson, mac) }

  @ReactMethod
  fun pinMake(teammateAccountId: String, spkiSha256: String, compared: Boolean, how: String, promise: Promise) =
      answer(promise) { pinMap(state.makePin(keys.ownShare(), keys.currentAccount(), teammateAccountId, spkiSha256, compared, how, now())) }

  @ReactMethod
  fun wrapDekToTeammate(type: String, id: String, spki: String, info: String, promise: Promise) =
      answer(promise) { core.base64url(state.wrapToTeammate(keys.ownShare(), keys.currentAccount(), bytes(spki, "teammate_unpinned"), info, keys.dek(type, id))) }

  @ReactMethod
  fun code(athleteAccountId: String, promise: Promise) =
      answer(promise) { core.teammateCode(athleteAccountId, keys.currentAccount(), ownSpki()) ?: throw LeaveCryptoCore.TeammateRefusal("sas_field") }

  @ReactMethod
  fun checkCode(text: String, teammateAccountId: String, spki: String, promise: Promise) =
      answer(promise) { core.checkTeammateCode(text, keys.currentAccount(), teammateAccountId, bytes(spki, "key")) }

  @ReactMethod
  fun sasStatus(athleteAccountId: String, teammateAccountId: String, promise: Promise) = answer(promise) {
    val s = state.status(athleteAccountId, teammateAccountId, now())
    Arguments.createMap().apply {
      putBoolean("canStart", s.canStart)
      putInt("started", s.started)
      putInt("unfinished", s.unfinished)
      if (s.nextAt == null) putNull("nextAt") else putDouble("nextAt", s.nextAt.toDouble())
    }
  }

  @ReactMethod
  fun sasCommit(runId: String, teammateAccountId: String, spki: String, promise: Promise) =
      answer(promise) { core.base64url(state.commit(runId, keys.currentAccount(), teammateAccountId, bytes(spki), now())) }

  @ReactMethod fun sasReveal(runId: String, nT: String, promise: Promise) = answer(promise) { core.base64url(state.reveal(runId, bytes(nT), now())) }

  @ReactMethod fun sasDigits(runId: String, promise: Promise) = answer(promise) { state.digitsA(runId, now()) }

  @ReactMethod
  fun sasAnswer(runId: String, athleteAccountId: String, commitment: String, promise: Promise) =
      answer(promise) { core.base64url(state.answer(runId, athleteAccountId, keys.currentAccount(), bytes(commitment), now())) }

  @ReactMethod fun sasCheck(runId: String, nA: String, promise: Promise) = answer(promise) { state.check(runId, bytes(nA), ownSpki(), now()) }

  @ReactMethod fun sasEnd(runId: String, finished: Boolean, promise: Promise) = answer(promise) { state.end(runId, finished); true }
}
