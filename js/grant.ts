import { holdsAccountMemory } from './accountMemory';
import { api } from './client';
import { crypto, type RecordType } from './crypto';
import { parseReadingSession } from './parse/misc';

/**
 * Session grants (API contract section 6). Before the server can read a private record
 * on the athlete's behalf, the app opens a session (POST /session), seals a fresh
 * session key to the server's KMS key and each needed DEK under that session key
 * (native, see LeaveCrypto.grant), registers it with POST /session/keys, and sends the
 * same grant as the X-Leave-Grant header on every request that touches those records.
 *
 * Grants live at most 15 minutes and are stateless on the server, so the app keeps one
 * per set of records and makes a new one when it expires or the set changes.
 *
 * Grant v2: a server that gives a `ticket` gets v2 grants, each key
 * sealed to the ticket, the key version, the exp, the use (app or mcp) and the record. With a ticket
 * the app never sends v1, and a v2 failure is not retried as v1. Once a ticket has come in this app
 * run, an answer without one is an error: a ticket can't be stripped
 * mid-run, and a restart after the server stops giving tickets returns to v1.
 */

type Session = { sessionId: string; serverPublicKey: string; keyVersion: string; exp: number; ticket?: string };

const TTL_SECONDS = 15 * 60;
const SAFETY_SECONDS = 30;

let session: Session | null = null;
let current: { header: string; exp: number; key: string } | null = null;
/** A ticket came in this app run (in memory only; cleared at sign-out, deletion and the process ending). */
let ticketSeen = false;

async function newSession(): Promise<Session> {
  const s = parseReadingSession(await api.post<unknown>('/session'));
  if (s.ticket) {
    ticketSeen = true;
  } else if (ticketSeen) {
    session = null;
    throw new Error('ticket_missing');
  }
  session = s;
  return s;
}

async function openSession(): Promise<Session> {
  const now = Math.floor(Date.now() / 1000);
  if (session && session.exp > now + SAFETY_SECONDS) {
    return session;
  }
  return newSession();
}

/** v2 with the session's ticket, v1 without one; never v1 for a session that has a ticket. */
function seal(s: Session, exp: number, use: 'app' | 'mcp', records: { id: string; type: RecordType }[]): Promise<{ body: string; header: string }> {
  return s.ticket ? crypto.grantV2(s.ticket, s.keyVersion, s.serverPublicKey, exp, use, records) : crypto.grant(s.sessionId, s.serverPublicKey, exp, records);
}

function keyOf(records: { id: string; type: RecordType }[]): string {
  return records
    .map(r => `${r.type}:${r.id}`)
    .sort()
    .join(',');
}

/**
 * A grant on its own, not registered and not cached: the body for POST
 * /mcp/clients/{id}/grant, which carries its own lifetime (15 minutes or 1 hour). Always on a
 * fresh session, so a ticket never expires in flight; v2's use is `mcp`.
 */
export async function sealGrant(records: { id: string; type: RecordType }[], ttlSeconds: number): Promise<{ body: Record<string, unknown>; exp: number }> {
  const s = await newSession();
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const g = await seal(s, exp, 'mcp', records);
  return { body: JSON.parse(g.body) as Record<string, unknown>, exp };
}

/**
 * 1.3, Talk's key requests: one item's grant in the X-Leave-Grant form, sealed to the server's key
 * and not registered as the turn's grant, for POST /talk/keys. It lives at most `ttlSeconds` (never
 * past the session).
 */
export async function sealHeader(records: { id: string; type: RecordType }[], ttlSeconds: number): Promise<string> {
  const s = await openSession();
  const exp = Math.min(s.exp, Math.floor(Date.now() / 1000) + ttlSeconds);
  return (await seal(s, exp, 'app', records)).header;
}

export const grants = {
  /**
   * The X-Leave-Grant header for these records, registering a new grant when needed.
   * The DEKs must already be in the native key cache (newRecordKey or import…).
   */
  async headerFor(records: { id: string; type: RecordType }[]): Promise<Record<string, string>> {
    const now = Math.floor(Date.now() / 1000);
    const key = keyOf(records);
    if (current && current.key === key && current.exp > now + SAFETY_SECONDS) {
      return { 'X-Leave-Grant': current.header };
    }
    const s = await openSession();
    const exp = Math.min(s.exp, now + TTL_SECONDS);
    const g = await seal(s, exp, 'app', records);
    await api.post('/session/keys', JSON.parse(g.body));
    current = { header: g.header, exp, key };
    return { 'X-Leave-Grant': g.header };
  },

  /** Sign-out, delete, or a server key change: drop everything and start over next time. The ticket guard stays for the run. */
  reset(): void {
    session = null;
    current = null;
  },
};

// The account's end (sign-out, deletion) clears the ticket guard too; a key change doesn't.
holdsAccountMemory(
  'the reading session',
  () => {
    grants.reset();
    ticketSeen = false;
  },
  () => ({ session: session ? 'held' : null, grant: current ? 'held' : null, ticketSeen: ticketSeen || null }),
);
