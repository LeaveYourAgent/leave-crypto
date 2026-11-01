// A reference, on Node's crypto only, for the three things two of an athlete's people check
// between their own phones before the athlete's phone shares with a Teammate's key:
//
//   1. the pin: the Teammate key the athlete's phone keeps, with a MAC under a key derived from
//      the athlete's share, so the server can store it for the athlete's other phones and can't
//      forge or change it;
//   2. the Teammate's code: the plain string in the QR the athlete's phone scans when the two are
//      together, and how the athlete's phone checks it;
//   3. the six digits for a call: a commit-reveal exchange the server only relays.
//
// The exact bytes are in vectors/teammate-v1.json's `spec`. `node teammate/check.mjs` holds this
// file to those vectors; the phones' code is held to the same file.
import { createHash, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const utf8 = s => Buffer.from(s, 'utf8');

/** One length-prefixed field: a 4-byte big-endian length, then the bytes. */
export function lp(bytes) {
  const b = Buffer.isBuffer(bytes) ? bytes : utf8(bytes);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length);
  return Buffer.concat([len, b]);
}
/** A hash or MAC input: the fields in order, each length-prefixed, the label first. */
export const fields = (...xs) => Buffer.concat(xs.map(lp));

/** Crockford base32, 26 characters, upper case only, at most 7ZZZ… (a 128-bit value). */
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
export const isUlid = s => typeof s === 'string' && ULID.test(s);

/** base64url without padding, and only its one canonical spelling of the 32 bytes. */
function hash32(text) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(text)) return null;
  const b = Buffer.from(text, 'base64url');
  return b.length === 32 && b.toString('base64url') === text ? b : null;
}

export const spkiSha256 = spkiDer => sha256(spkiDer);

// ---------- 1. The pin ----------

export const PIN_LABEL = 'leave:v1:teammate-pin';
const PIN_HOW = { true: ['scan', 'call'], false: ['none'] };

/** The MAC key: HKDF-SHA256 of the athlete's share, salt the athlete's account id, info the label. */
export function pinKey(share, athleteAccountId) {
  return Buffer.from(hkdfSync('sha256', share, utf8(athleteAccountId), utf8(PIN_LABEL), 32));
}

/**
 * A pin record is refused before any MAC is made or checked when it is not one of the three
 * kinds the phone writes: compared by a scan, compared on a call, or kept without comparing.
 */
export function pinRecordProblem(r) {
  if (!r || typeof r !== 'object') return 'pin_record';
  const keys = Object.keys(r).sort().join(',');
  if (keys !== 'at,compared,how,spkiSha256,teammateAccountId') return 'pin_record';
  if (!isUlid(r.teammateAccountId)) return 'pin_record';
  if (!hash32(r.spkiSha256)) return 'pin_record';
  if (typeof r.compared !== 'boolean' || !PIN_HOW[r.compared].includes(r.how)) return 'pin_record';
  if (!Number.isSafeInteger(r.at) || r.at < 0) return 'pin_record';
  return null;
}

export function pinMacInput(r) {
  return fields(PIN_LABEL, r.teammateAccountId, hash32(r.spkiSha256), r.compared ? 'true' : 'false', r.how, String(r.at));
}

export function pinMac(share, athleteAccountId, r) {
  const problem = pinRecordProblem(r);
  if (problem) throw new Error(problem);
  return createHmac('sha256', pinKey(share, athleteAccountId)).update(pinMacInput(r)).digest();
}

/** true only for a well-formed record whose MAC is the one this share makes. */
export function verifyPin(share, athleteAccountId, r, macText) {
  if (pinRecordProblem(r)) return false;
  const mac = hash32(macText ?? '');
  return mac !== null && timingSafeEqual(mac, pinMac(share, athleteAccountId, r));
}

/**
 * The wrap gate: a record key goes to the Teammate's key only under a pin that verifies and names
 * that same key. null means the wrap may go ahead; otherwise the reason it can't.
 */
export function wrapRefusal(share, athleteAccountId, pin, spkiDer) {
  if (!pin) return 'teammate_unpinned';
  if (!verifyPin(share, athleteAccountId, pin.record, pin.mac)) return 'teammate_unpinned';
  if (!timingSafeEqual(hash32(pin.record.spkiSha256), spkiSha256(spkiDer))) return 'teammate_unpinned';
  return null;
}

// ---------- 2. The Teammate's code (QR) ----------

export const CODE_VERSION = 'LEAVE-TM1';

/** What the Teammate's phone shows, for one athlete, from its own key. */
export function teammateCode(athleteAccountId, teammateAccountId, ownSpkiDer) {
  if (!isUlid(athleteAccountId) || !isUlid(teammateAccountId)) throw new Error('code_field');
  return `${CODE_VERSION}:${athleteAccountId}:${teammateAccountId}:${spkiSha256(ownSpkiDer).toString('base64url')}`;
}

/**
 * The athlete's phone's check of a scanned string, in this order, the first failure deciding:
 *   format   — not exactly four `:`-separated fields of printable ASCII with no spaces, an id
 *              that isn't an upper-case ULID, or a hash that isn't 43 canonical base64url characters
 *   version  — the first field isn't exactly LEAVE-TM1
 *   athlete  — the code was made for another athlete (not this phone's own account)
 *   teammate — the code is from another account than the Teammate the server named
 *   key      — the hash isn't SHA-256 of the key this phone received for that Teammate
 * The person sees one sentence for every refusal; the reason is for the app's own diagnostics.
 */
export function checkTeammateCode(text, myAccountId, teammateAccountId, receivedSpkiDer) {
  if (typeof text !== 'string' || !/^[\x21-\x7e]+$/.test(text)) return { ok: false, reason: 'format' };
  const parts = text.split(':');
  if (parts.length !== 4) return { ok: false, reason: 'format' };
  const [version, athlete, teammate, hash] = parts;
  if (version !== CODE_VERSION) return { ok: false, reason: 'version' };
  if (!isUlid(athlete) || !isUlid(teammate)) return { ok: false, reason: 'format' };
  const h = hash32(hash);
  if (!h) return { ok: false, reason: 'format' };
  if (athlete !== myAccountId) return { ok: false, reason: 'athlete' };
  if (teammate !== teammateAccountId) return { ok: false, reason: 'teammate' };
  if (!timingSafeEqual(h, spkiSha256(receivedSpkiDer))) return { ok: false, reason: 'key' };
  return { ok: true };
}

// ---------- 3. Six digits on a call (commit-reveal) ----------

export const SAS_COMMIT_LABEL = 'leave:v1:teammate-sas-commit';
export const SAS_LABEL = 'leave:v1:teammate-sas';

function nonce32(n) {
  if (!Buffer.isBuffer(n) || n.length !== 32) throw new Error('sas_field');
  return n;
}
function idsOf(ids) {
  const { runId, athleteAccountId, teammateAccountId } = ids;
  if (typeof runId !== 'string' || runId.length === 0 || !isUlid(athleteAccountId) || !isUlid(teammateAccountId)) throw new Error('sas_field');
  return [runId, athleteAccountId, teammateAccountId];
}

/** The athlete's phone's commitment, sent first: it binds the key it received and its nonce. */
export function sasCommit(ids, teammateSpkiDer, nA) {
  return sha256(fields(SAS_COMMIT_LABEL, ...idsOf(ids), teammateSpkiDer, nonce32(nA)));
}

/**
 * The Teammate's phone's check of the revealed nonce against the commitment, with its own key.
 * false (the comparison didn't complete, no digits) when the server swapped the key toward the
 * athlete, changed the commitment, or relayed another nonce.
 */
export function sasOpens(ids, ownSpkiDer, nA, commitment) {
  const c = sasCommit(ids, ownSpkiDer, nA);
  return Buffer.isBuffer(commitment) && commitment.length === 32 && timingSafeEqual(c, commitment);
}

/** The six digits both phones show: the first 4 bytes of the hash, unsigned big-endian, mod 10^6. */
export function sasNumber(ids, teammateSpkiDer, nA, nT) {
  const d = sha256(fields(SAS_LABEL, ...idsOf(ids), teammateSpkiDer, nonce32(nA), nonce32(nT)));
  return { uint32: d.readUInt32BE(0), digits: String(d.readUInt32BE(0) % 1_000_000).padStart(6, '0') };
}

/** "482913" → "482 913", the form a phone approval already shows. */
export const sasLine = digits => `${digits.slice(0, 3)} ${digits.slice(3)}`;
