package com.leaveyouragent.leave.crypto

import android.content.Context
import com.google.android.gms.auth.blockstore.Blockstore
import com.google.android.gms.auth.blockstore.DeleteBytesRequest
import com.google.android.gms.auth.blockstore.RetrieveBytesRequest
import com.google.android.gms.auth.blockstore.StoreBytesData
import com.google.android.gms.tasks.Task
import com.google.android.gms.tasks.Tasks
import java.util.concurrent.TimeUnit

/**
 * Google's Block Store, as the one `CarryStore` there is (ShareCarry.kt has the rule for using
 * it). Block Store keeps up to 16 small entries for an app, hands them only to the same app
 * signed with the same key, and restores them when a person sets up a new phone from their
 * Google backup.
 *
 * Every entry is stored with cloud backup on, which is only ever asked for after the phone has
 * said the backup is end-to-end encrypted. Google's own words (developer.android.com,
 * identity/block-store, read 2026-10-09): "In order for end-to-end encryption to be made
 * available, the device must be running Android 9 or higher, and the user must have set a
 * screen lock".
 *
 * Each call waits for Google Play services and must not be made on the main thread. A phone
 * without Google Play services answers every question with an error, which ShareCarry reads as
 * "not carried" and "nothing found".
 */
class PlayBlockStore(context: Context) : CarryStore {
  private val client = Blockstore.getClient(context.applicationContext)

  private fun <T> wait(task: Task<T>): T = Tasks.await(task, 10, TimeUnit.SECONDS)

  override fun endToEndEncrypted(): Boolean = wait(client.isEndToEndEncryptionAvailable)

  override fun put(name: String, secret: ByteArray) {
    wait(client.storeBytes(StoreBytesData.Builder().setBytes(secret).setKey(name).setShouldBackupToCloud(true).build()))
  }

  override fun get(name: String): ByteArray? =
      wait(client.retrieveBytes(RetrieveBytesRequest.Builder().setKeys(listOf(name)).build())).blockstoreDataMap[name]?.bytes

  override fun delete(name: String) {
    wait(client.deleteBytes(DeleteBytesRequest.Builder().setKeys(listOf(name)).build()))
  }
}
