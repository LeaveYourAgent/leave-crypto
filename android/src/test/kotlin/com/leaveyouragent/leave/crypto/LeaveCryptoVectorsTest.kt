package com.leaveyouragent.leave.crypto

import java.io.File

/** The shared vectors on this computer (see LeaveCryptoVectors): vectors/v1.json at the top of this repository. */
class LeaveCryptoVectorsTest : LeaveCryptoVectors() {
  override fun vectorsText(): String = File("../vectors/v1.json").readText()
}
