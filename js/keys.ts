import { holdsAccountMemory } from './accountMemory';
import { api, ApiError } from './client';
import { crypto, type RecordType } from './crypto';
import { parseKeyRows } from './parse/misc';

/**
 * Record keys on this phone (contract v1.6.1, section 6). A DEK made here stays in
 * the native cache for the session; one made on another phone, or lost to a relaunch,
 * comes back as its share wrap from GET /records/keys and is opened natively with the
 * synced share. Nothing about a key is ever kept in JavaScript.
 */

const known = new Set<string>();


export async function ensureRecordKey(type: RecordType, id: string): Promise<void> {
  const k = `${type}:${id}`;
  if (known.has(k) || (await crypto.hasKey(type, id))) {
    known.add(k);
    return;
  }
  const rows = parseKeyRows(await api.get<unknown>(`/records/keys?ids=${encodeURIComponent(id)}`));
  const row = rows.find(r => r.recordId === id);
  if (!row?.shareWrappedDek) {
    throw new ApiError('no_key', "This phone has no key for that record yet.", 0);
  }
  await crypto.importShareWrappedDek(type, id, row.shareWrappedDek);
  known.add(k);
}

/** The same for many records of one type, 200 ids to a call (the route's limit). */
export async function ensureRecordKeys(type: RecordType, ids: string[]): Promise<void> {
  const missing: string[] = [];
  for (const id of ids) {
    const k = `${type}:${id}`;
    if (known.has(k)) {
      continue;
    }
    if (await crypto.hasKey(type, id)) {
      known.add(k);
    } else {
      missing.push(id);
    }
  }
  for (let at = 0; at < missing.length; at += 200) {
    const batch = missing.slice(at, at + 200);
    const rows = parseKeyRows(await api.get<unknown>(`/records/keys?ids=${batch.map(encodeURIComponent).join(',')}`));
    for (const row of rows) {
      if (row.shareWrappedDek && batch.includes(row.recordId)) {
        await crypto.importShareWrappedDek(type, row.recordId, row.shareWrappedDek);
        known.add(`${type}:${row.recordId}`);
      }
    }
  }
}

/** A key made on this phone in this session. */
export function rememberRecordKey(type: RecordType, id: string): void {
  known.add(`${type}:${id}`);
}

/** Sign-out or deletion: the native cache is cleared by the caller; forget what was in it. */
export function forgetRecordKeys(): void {
  known.clear();
}

holdsAccountMemory('record keys', forgetRecordKeys, () => [...known]);
