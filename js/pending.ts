import { api, ApiError } from './client';
import { crypto, type RecordType } from './crypto';
import { tokenStore } from './tokens';
import { parseKeyRows } from './parse/misc';

/**
 * Records the server creates (Talk strands and receipts, Web threads, notes and contracts
 * added from an AI app) arrive with their data key wrapped only to the account's public
 * key. The phone finishes the job (contract section 6): it opens each pending wrap with
 * the account key (HPKE, info leave:v1:pending:<recordId>), wraps the key to the share
 * like every other record, and stores that with PUT /records/keys. Until then the record's key
 * is held only wrapped to the account's public key, so this phone can't use it in a grant yet.
 * Needs the account key to be registered.
 */


const MAX_ROUNDS = 10;
let running: Promise<number> | null = null;

async function run(): Promise<number> {
  const accountId = (await tokenStore.get())?.accountId;
  if (!accountId || !crypto.available()) {
    return 0;
  }
  let done = 0;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const pending = parseKeyRows(await api.get<unknown>('/records/keys?pending=true'));
    if (pending.length === 0) {
      break;
    }
    const rewrapped: { recordId: string; shareWrappedDek: string }[] = [];
    for (const p of pending) {
      if (!p.accountWrappedDek) {
        continue;
      }
      try {
        // The type goes to the phone's crypto as the server sent it; one it doesn't know fails there and is skipped.
        const r = await crypto.importPendingDek(p.type as RecordType, p.recordId, p.accountWrappedDek, `leave:v1:pending:${p.recordId}`, accountId);
        rewrapped.push({ recordId: p.recordId, shareWrappedDek: r.shareWrappedDek });
      } catch {
        // A wrap this phone cannot open (made to an older account key) is left for rotation to fix.
      }
    }
    if (rewrapped.length === 0) {
      break;
    }
    try {
      await api.put('/records/keys', rewrapped);
      done += rewrapped.length;
    } catch (e) {
      // A record undone in between fails the whole batch: read the list again and retry.
      if (!(e instanceof ApiError && e.code === 'unknown_records')) {
        throw e;
      }
    }
  }
  return done;
}

/** Finish every pending wrap. Concurrent callers share one run. Returns how many were completed. */
export function completePending(): Promise<number> {
  if (!running) {
    running = run().finally(() => {
      running = null;
    });
  }
  return running;
}
