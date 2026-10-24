import { holdsAccountMemory } from './accountMemory';
import { api } from './client';
import { contractExtractions, uploadIdOf } from './contracts';
import { crypto } from './crypto';
import { sealHeader } from './grant';
import { ensureRecordKey } from './keys';
import { webData } from './web';

/**
 * Talk's key requests (1.3). A reply that needs one contract's full terms, or why one Web thread
 * fits, asks the phone for that one item's key in the middle of the turn:
 * `key_request { requestId, kind, id }`. The phone answers with a fresh grant holding only that
 * item (`POST /talk/keys { requestId, grant }`, in the X-Leave-Grant form, sealed to the server's
 * key by grant.ts's sealHeader), and only when all hold:
 *
 * - the turn is one this phone started and is still open (the app's Talk code, not in this
 *   repository, calls this only then);
 * - the kind is a contract (one of this account's, with fields on the phone) or a stored Web thread
 *   (never a live one: the phone holds no key for a live thread);
 * - the phone holds that item's key;
 * - the request id hasn't been answered (the app's Talk code keeps that per turn);
 * - fewer than `MAX_PER_MINUTE` answers in the last minute, the server's own limit.
 *
 * Anything else is not answered, and the server's wait ends the tool as it says.
 *
 * `./contracts` and `./web` are the app's lists of this account's contracts and Web threads, and
 * `./client` and `./accountMemory` its API client and sign-out reset; none of them is in this
 * repository.
 */
export type KeyRequest = { requestId: string; kind: 'contract' | 'thread'; id: string };

/** How long the one-item grant lives: long enough for the reply, well under a session grant's 15 minutes. */
export const KEY_GRANT_SECONDS = 5 * 60;
export const MAX_PER_MINUTE = 10;

let answeredAt: number[] = [];

export function parseKeyRequest(data: unknown): KeyRequest | null {
  const d = data as { requestId?: unknown; kind?: unknown; id?: unknown } | null;
  if (!d || typeof d.requestId !== 'string' || !d.requestId || typeof d.id !== 'string' || !d.id) {
    return null;
  }
  return d.kind === 'contract' || d.kind === 'thread' ? { requestId: d.requestId, kind: d.kind, id: d.id } : null;
}

/** What the working label says while the key goes: the contract's brand when the phone knows it. */
export function keyRequestLabel(r: KeyRequest): string {
  if (r.kind === 'thread') {
    return 'OPENING A THREAD FROM YOUR WEB';
  }
  const brand = contractExtractions().find(c => c.contractId === r.id)?.fields.brand.name;
  return brand ? `OPENING YOUR ${brand.toUpperCase()} CONTRACT` : 'OPENING YOUR CONTRACT';
}

/** The record whose key answers this request, or null when the phone may not answer it. */
async function recordFor(r: KeyRequest): Promise<{ id: string; type: 'contract' | 'thread' } | null> {
  if (r.kind === 'contract') {
    const uploadId = uploadIdOf(r.id);
    if (!uploadId || !contractExtractions().some(c => c.contractId === r.id)) {
      return null;
    }
    await ensureRecordKey('contract', uploadId);
    return (await crypto.hasKey('contract', uploadId)) ? { id: uploadId, type: 'contract' } : null;
  }
  if (!webData.threads().some(t => t.recordId === r.id)) {
    return null;
  }
  await ensureRecordKey('thread', r.id);
  return (await crypto.hasKey('thread', r.id)) ? { id: r.id, type: 'thread' } : null;
}

/** Answers one key request; 'refused' when the phone may not, and nothing is sent then. */
export async function answerKeyRequest(r: KeyRequest, now: number = Date.now()): Promise<'sent' | 'refused'> {
  answeredAt = answeredAt.filter(t => t > now - 60_000);
  if (answeredAt.length >= MAX_PER_MINUTE) {
    return 'refused';
  }
  const record = await recordFor(r).catch(() => null);
  if (!record) {
    return 'refused';
  }
  answeredAt.push(now);
  const grant = await sealHeader([record], KEY_GRANT_SECONDS);
  await api.post('/talk/keys', { requestId: r.requestId, grant });
  return 'sent';
}

holdsAccountMemory(
  "Talk's key answers in the last minute",
  () => {
    answeredAt = [];
  },
  () => answeredAt,
);
