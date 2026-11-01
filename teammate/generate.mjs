// Writes vectors/teammate-v1.json from teammate/reference.mjs and the test keys already in
// vectors/v1.json (`node teammate/generate.mjs`). Every nonce is derived from a fixed string, so
// running it again writes the same file.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import * as T from './reference.mjs';

const here = new URL('..', import.meta.url);
const v1 = JSON.parse(readFileSync(new URL('vectors/v1.json', here), 'utf8'));
const b64 = b => Buffer.from(b).toString('base64url');
const unb64 = s => Buffer.from(s, 'base64url');
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const fixed = label => createHash('sha256').update(`leave-crypto teammate vector ${label}`).digest();

const ath = v1.accountKey.find(k => k.name === 'athlete account key');
const tm = v1.accountKey.find(k => k.name === 'teammate account key');
const other = v1.hpke.find(h => h.name === 'share wrapped to a new device');
const keys = {
  athlete: { accountId: ath.accountId, share: ath.share, publicKeySpki: ath.publicKeySpki },
  teammate: { accountId: tm.accountId, publicKeySpki: tm.publicKeySpki },
  other: { note: "another P-256 key (v1.json hpke 'share wrapped to a new device'), standing for a key the server swapped in", publicKeySpki: other.recipientPublicKeySpki },
  otherAthleteAccountId: '01J8Z3V4Q6X7R2M9K5T0W1Y8AC',
  otherTeammateAccountId: '01J8Z3V4Q6X7R2M9K5T0W1Y8AD',
};
const share = unb64(keys.athlete.share);
const A = keys.athlete.accountId, TM = keys.teammate.accountId;
const kT = unb64(keys.teammate.publicKeySpki), kX = unb64(keys.other.publicKeySpki);
const hT = b64(T.spkiSha256(kT)), hX = b64(T.spkiSha256(kX));

// ---------- pin ----------
const records = [
  ['compared by a scan', { teammateAccountId: TM, spkiSha256: hT, compared: true, how: 'scan', at: 1793570400 }],
  ['compared on a call', { teammateAccountId: TM, spkiSha256: hT, compared: true, how: 'call', at: 1793570401 }],
  ['kept without comparing', { teammateAccountId: TM, spkiSha256: hT, compared: false, how: 'none', at: 1793570402 }],
  ['the Teammate removed (a tombstone)', { teammateAccountId: TM, spkiSha256: T.ZERO_HASH, compared: false, how: 'removed', at: 1793570403 }],
];
const pinCases = records.map(([name, record]) => ({ name, record, macInput: b64(T.pinMacInput(record)), mac: b64(T.pinMac(share, A, record)) }));
const good = pinCases[0];
const flip = (name, patch) => ({ name, record: { ...good.record, ...patch }, mac: good.mac, expect: 'mac' });
const pinRefusals = [
  flip('another Teammate account', { teammateAccountId: keys.otherTeammateAccountId }),
  flip('another key hash', { spkiSha256: hX }),
  flip('how changed from scan to call', { how: 'call' }),
  flip('a later time', { at: good.record.at + 1 }),
  { name: 'the MAC of another athlete (another share)', record: good.record, mac: b64(T.pinMac(fixed('other share'), A, good.record)), expect: 'mac' },
  { name: 'the right share, made under another athlete id', record: good.record, mac: b64(T.pinMac(share, keys.otherAthleteAccountId, good.record)), expect: 'mac' },
  { name: 'compared true with how none', record: { ...good.record, how: 'none' }, mac: good.mac, expect: 'pin_record' },
  { name: 'compared false with how scan', record: { ...good.record, compared: false }, mac: good.mac, expect: 'pin_record' },
  { name: 'compared as a string', record: { ...good.record, compared: 'true' }, mac: good.mac, expect: 'pin_record' },
  { name: 'how not one of scan, call, none, removed', record: { ...good.record, how: 'qr' }, mac: good.mac, expect: 'pin_record' },
  { name: 'at not a whole number', record: { ...good.record, at: 1793570400.5 }, mac: good.mac, expect: 'pin_record' },
  { name: 'an extra field', record: { ...good.record, note: 'x' }, mac: good.mac, expect: 'pin_record' },
  { name: 'a hash with padding', record: { ...good.record, spkiSha256: `${hT}=` }, mac: good.mac, expect: 'pin_record' },
  { name: 'a lower-case Teammate id', record: { ...good.record, teammateAccountId: TM.toLowerCase() }, mac: good.mac, expect: 'pin_record' },
  { name: 'a MAC one byte short', record: good.record, mac: b64(unb64(good.mac).subarray(0, 31)), expect: 'mac' },
  { name: 'the zero hash with how none', record: { ...good.record, spkiSha256: T.ZERO_HASH, compared: false, how: 'none' }, mac: good.mac, expect: 'pin_record' },
  { name: 'the zero hash with how scan', record: { ...good.record, spkiSha256: T.ZERO_HASH }, mac: good.mac, expect: 'pin_record' },
  { name: 'compared true with how removed', record: { ...pinCases[3].record, compared: true }, mac: pinCases[3].mac, expect: 'pin_record' },
  { name: 'a removal with a non-zero hash', record: { ...pinCases[3].record, spkiSha256: hT }, mac: pinCases[3].mac, expect: 'pin_record' },
  { name: 'a tombstone whose at was changed', record: { ...pinCases[3].record, at: pinCases[3].record.at + 1 }, mac: pinCases[3].mac, expect: 'mac' },
];
for (const r of pinRefusals) {
  const problem = T.pinRecordProblem(r.record);
  if ((problem ? 'pin_record' : (T.verifyPin(share, A, r.record, r.mac) ? null : 'mac')) !== r.expect) throw new Error(`pin refusal not as expected: ${r.name}`);
}
const pinOf = c => ({ record: c.record, mac: c.mac });
const wrap = [
  { name: 'pinned to this key: wrap', pin: pinOf(pinCases[0]), spki: keys.teammate.publicKeySpki, expect: null },
  { name: 'kept without comparing is still a pin: wrap', pin: pinOf(pinCases[2]), spki: keys.teammate.publicKeySpki, expect: null },
  { name: 'no pin', pin: null, spki: keys.teammate.publicKeySpki, expect: 'teammate_unpinned' },
  { name: 'the server sends another key', pin: pinOf(pinCases[0]), spki: keys.other.publicKeySpki, expect: 'teammate_unpinned' },
  { name: 'a pin the server changed to the other key', pin: { record: { ...good.record, spkiSha256: hX }, mac: good.mac }, spki: keys.other.publicKeySpki, expect: 'teammate_unpinned' },
  { name: 'the newest pin is a removal: no wrap to anyone', pin: pinOf(pinCases[3]), spki: keys.teammate.publicKeySpki, expect: 'teammate_removed' },
];
for (const w of wrap) if (T.wrapRefusal(share, A, w.pin, unb64(w.spki)) !== w.expect) throw new Error(`wrap not as expected: ${w.name}`);

// A pin record read from JSON text: `at` only as a plain integer.
const recordText = at => `{"teammateAccountId":"${TM}","spkiSha256":"${hT}","compared":true,"how":"scan","at":${at}}`;
const jsonText = [
  { name: 'at as a plain integer', text: recordText('1793570400'), expect: null, mac: good.mac },
  { name: 'at written with a fraction (1793570400.0)', text: recordText('1793570400.0'), expect: 'pin_record' },
  { name: 'at written with an exponent (1.7935704e9)', text: recordText('1.7935704e9'), expect: 'pin_record' },
  { name: 'at written with a minus sign (-0)', text: recordText('-0'), expect: 'pin_record' },
  { name: 'at with a leading zero (01793570400) is not JSON', text: recordText('01793570400'), expect: 'pin_record' },
  { name: 'at as a string', text: recordText('"1793570400"'), expect: 'pin_record' },
];
for (const j of jsonText) {
  const r = T.parsePinRecord(j.text);
  if ((r.problem ?? null) !== j.expect) throw new Error(`json text: ${j.name}`);
  if (!r.problem && !T.verifyPin(share, A, r.record, j.mac)) throw new Error(`json text mac: ${j.name}`);
}

// The newest pin a phone has seen (its cache), step by step: each step's cache is the one before's result.
const pinAt = (name, teammateAccountId, spkiSha256, compared, how, at) => {
  const record = { teammateAccountId, spkiSha256, compared, how, at };
  return { name, record, mac: b64(T.pinMac(share, A, record)) };
};
const t0 = 1793571000;
const X = keys.otherTeammateAccountId;
const pOld = pinAt('Teammate, scanned', TM, hT, true, 'scan', t0);
const pNew = pinAt('Teammate, compared on a call later', TM, hT, true, 'call', t0 + 10);
const pEqualAt = pinAt('Teammate, kept without comparing, at the same time as the call', TM, hT, false, 'none', t0 + 10);
const pFormer = pinAt('a former Teammate, older', X, hX, true, 'scan', t0 - 100);
const pNewTeammate = pinAt('a new Teammate, set on another phone', X, hX, false, 'none', t0 + 20);
const pRemoved = pinAt('the new Teammate removed', X, T.ZERO_HASH, false, 'removed', t0 + 30);
const pAfter = pinAt('the first Teammate again, after the removal', TM, hT, true, 'scan', t0 + 40);
const steps = [
  ['no cache: the first served pin that verifies is taken', pOld],
  ['a newer pin replaces', pNew],
  ['an older pin that verifies is refused', pOld],
  ['the same time but a different record is refused', pEqualAt],
  ['the identical pin changes nothing', pNew],
  ["a former Teammate's older pin is refused", pFormer],
  ["a new Teammate's newer pin replaces", pNewTeammate],
  ['a pin with a bad MAC is refused', { name: 'forged', record: { ...pAfter.record }, mac: pNew.mac }],
  ['a malformed pin is refused', { name: 'malformed', record: { ...pAfter.record, how: 'qr' }, mac: pAfter.mac }],
  ['a newer removal replaces', pRemoved],
  ['an older pin after the removal is refused', pNew],
  ['a newer pin after the removal replaces', pAfter],
];
let cacheNow = null;
const cacheSteps = steps.map(([name, served]) => {
  const before = cacheNow;
  const r = T.acceptServedPin(share, A, before, { record: served.record, mac: served.mac });
  cacheNow = r.cache;
  const step = { name, cache: before, served: { record: served.record, mac: served.mac }, expect: r.result, expectCache: r.cache };
  if (served === pRemoved) step.wrapAfter = { spki: keys.other.publicKeySpki, expect: T.wrapRefusal(share, A, r.cache, kX) };
  return step;
});
const expected = ['accepted', 'accepted', 'pin_older', 'pin_older', 'same', 'pin_older', 'accepted', 'mac', 'pin_record', 'accepted', 'pin_older', 'accepted'];
if (JSON.stringify(cacheSteps.map(s => s.expect)) !== JSON.stringify(expected)) throw new Error(`cache steps: ${cacheSteps.map(s => s.expect)}`);
if (cacheSteps[9].wrapAfter.expect !== 'teammate_removed') throw new Error('wrap after removal');
const writeAtCases = [
  { name: 'the clock is behind the newest pin seen', nowSeconds: t0 + 5, newestSeenAt: t0 + 40, at: T.writeAt(t0 + 5, t0 + 40) },
  { name: 'the clock is ahead of it', nowSeconds: t0 + 100, newestSeenAt: t0 + 40, at: T.writeAt(t0 + 100, t0 + 40) },
  { name: 'the clock equals it', nowSeconds: t0 + 40, newestSeenAt: t0 + 40, at: T.writeAt(t0 + 40, t0 + 40) },
  { name: 'no pin seen yet', nowSeconds: t0, newestSeenAt: null, at: T.writeAt(t0, null) },
];
if (writeAtCases.map(w => w.at - t0).join() !== '41,100,41,0') throw new Error('writeAt');

// ---------- code ----------
const text = T.teammateCode(A, TM, kT);
const swap = (i, v) => text.split(':').map((p, j) => (j === i ? v : p)).join(':');
const codeChecks = [
  ['the right code', text, 'ok'],
  ['a newline after it', `${text}\n`, 'format'],
  ['a space before it', ` ${text}`, 'format'],
  ['empty', '', 'format'],
  ['a fifth field', `${text}:x`, 'format'],
  ['three fields', text.split(':').slice(0, 3).join(':'), 'format'],
  ['a URL', `https://leaveyouragent.com/${text}`, 'format'],
  ['the athlete id in lower case', swap(1, A.toLowerCase()), 'format'],
  ['an id with I, L, O or U', swap(2, `${TM.slice(0, 25)}U`), 'format'],
  ['an id 25 characters long', swap(2, TM.slice(0, 25)), 'format'],
  ['an id above the ULID range', swap(1, `8${A.slice(1)}`), 'format'],
  ['the hash with padding', swap(3, `${hT}=`), 'format'],
  ['a standard-base64 character in the hash', swap(3, `${hT.slice(0, 10)}+${hT.slice(11)}`), 'format'],
  ['the hash in a non-canonical spelling (its last character has unused bits set)', swap(3, hT.slice(0, 42) + B64[B64.indexOf(hT[42]) + 1]), 'format'],
  ['a 31-byte hash', swap(3, b64(unb64(hT).subarray(0, 31))), 'format'],
  ['version 2', `LEAVE-TM2${text.slice(9)}`, 'version'],
  ['the version in lower case', `leave-tm1${text.slice(9)}`, 'version'],
  ['a code made for another athlete', T.teammateCode(keys.otherAthleteAccountId, TM, kT), 'athlete'],
  ['athlete and Teammate ids swapped', T.teammateCode(TM, A, kT), 'athlete'],
  ['a code from another account', T.teammateCode(A, keys.otherTeammateAccountId, kT), 'teammate'],
  ['a code from another key', T.teammateCode(A, TM, kX), 'key'],
].map(([name, t, expect]) => ({ name, text: t, expect }));
for (const c of codeChecks) {
  const r = T.checkTeammateCode(c.text, A, TM, kT);
  if ((r.ok ? 'ok' : r.reason) !== c.expect) throw new Error(`code check not as expected: ${c.name} → ${r.reason}`);
}
const keyChanged = { name: 'the right code, but the server sent this phone another key for the Teammate', text, receivedSpki: keys.other.publicKeySpki, expect: 'key' };
if (T.checkTeammateCode(text, A, TM, kX).reason !== 'key') throw new Error('key-changed check');

// ---------- six digits ----------
const ids = { runId: '01J9A2B3C4D5E6F7G8H9J0K1M2', athleteAccountId: A, teammateAccountId: TM };
const run = (name, nA, nT, extra = {}) => {
  const c = T.sasCommit(ids, kT, nA);
  const n = T.sasNumber(ids, kT, nA, nT);
  return { name, ...ids, spkiAsAthleteReceived: keys.teammate.publicKeySpki, teammateOwnSpki: keys.teammate.publicKeySpki, nA: b64(nA), nT: b64(nT), commitment: b64(c), opens: T.sasOpens(ids, kT, nA, c), uint32: n.uint32, digits: n.digits, line: T.sasLine(n.digits), ...extra };
};
// Search fixed nonces for the cases an implementation gets wrong: a leading zero, the top bit
// set (a signed 32-bit read goes negative), and a value in the last, partial block above
// 4,294,000,000, where mod 10^6 lands in 0…967,295.
const want = [
  ['an ordinary run', n => n >= 100_000 && n < 2 ** 31],
  ['digits with a leading zero', n => n % 1_000_000 < 100_000],
  ['the first byte at 0x80 or above', n => n >= 2 ** 31 && n < 4_294_000_000],
  ['a value in the last partial block (≥ 4,294,000,000)', n => n >= 4_294_000_000],
];
const sas = [];
for (const [name, test] of want) {
  for (let i = 0; i < 1_000_000; i++) {
    const nA = fixed(`nA ${name} ${i}`), nT = fixed(`nT ${name} ${i}`);
    if (test(T.sasNumber(ids, kT, nA, nT).uint32)) { sas.push(run(name, nA, nT)); break; }
  }
}
if (sas.length !== want.length) throw new Error('a SAS case was not found');
const base = sas[0];
const nA0 = unb64(base.nA), nT0 = unb64(base.nT), c0 = unb64(base.commitment);
const swappedTowardAthlete = (() => {
  const c = T.sasCommit(ids, kX, nA0);
  return { name: 'the server gave the athlete another key: the Teammate\'s phone, with its own key, finds the commitment does not open', ...ids, spkiAsAthleteReceived: keys.other.publicKeySpki, teammateOwnSpki: keys.teammate.publicKeySpki, nA: base.nA, commitment: b64(c), opens: T.sasOpens(ids, kT, nA0, c) };
})();
const otherNonce = { name: 'the server relays another nA than the one committed', ...ids, teammateOwnSpki: keys.teammate.publicKeySpki, nA: b64(fixed('relayed nA')), commitment: base.commitment, opens: T.sasOpens(ids, kT, fixed('relayed nA'), c0) };
if (swappedTowardAthlete.opens || otherNonce.opens) throw new Error('a refused SAS opened');
const sasBinding = [
  ['another run id', { ...ids, runId: '01J9A2B3C4D5E6F7G8H9J0K1M3' }],
  ['athlete and Teammate ids swapped', { ...ids, athleteAccountId: TM, teammateAccountId: A }],
].map(([name, other]) => ({ name, ...other, nA: base.nA, nT: base.nT, commitment: b64(T.sasCommit(other, kT, nA0)), digits: T.sasNumber(other, kT, nA0, nT0).digits }));
for (const s of sasBinding) if (s.commitment === base.commitment) throw new Error(`binding: ${s.name}`);
// Why every field is length-prefixed: ("AB", "C") and ("A", "BC") are the same bytes joined
// plainly and different bytes here. The hex shows the exact encoding.
const lpExample = {
  note: 'the fields ("AB", "C") and ("A", "BC"): equal when joined plainly, different when length-prefixed',
  plainJoinEqual: Buffer.from('ABC').equals(Buffer.from('A' + 'BC')),
  first: { fields: ['AB', 'C'], hex: T.fields('AB', 'C').toString('hex') },
  second: { fields: ['A', 'BC'], hex: T.fields('A', 'BC').toString('hex') },
};
if (lpExample.first.hex === lpExample.second.hex) throw new Error('lp');
const sasRefusals = [
  { name: 'nA of 31 bytes', nA: b64(nA0.subarray(0, 31)), nT: base.nT, expect: 'sas_field' },
  { name: 'nT of 33 bytes', nA: base.nA, nT: b64(Buffer.concat([nT0, Buffer.from([0])])), expect: 'sas_field' },
  { name: 'an empty run id', runId: '', nA: base.nA, nT: base.nT, expect: 'sas_field' },
  { name: 'a run id of 65 characters', runId: 'R'.repeat(65), nA: base.nA, nT: base.nT, expect: 'sas_field' },
  { name: 'a run id with a space', runId: '01J9A2B3C4D5 E6F7G8H9J0K1M2', nA: base.nA, nT: base.nT, expect: 'sas_field' },
  { name: 'a run id with a non-ASCII character', runId: '01J9A2B3C4D5É6F7G8H9J0K1M2', nA: base.nA, nT: base.nT, expect: 'sas_field' },
  { name: 'a run id of printable ASCII that is not a ULID', runId: 'run-1', nA: base.nA, nT: base.nT, expect: 'sas_field' },
  { name: 'a run id in lower case', runId: '01j9a2b3c4d5e6f7g8h9j0k1m2', nA: base.nA, nT: base.nT, expect: 'sas_field' },
];
for (const r of sasRefusals) {
  let got = null;
  try { T.sasNumber({ ...ids, ...(r.runId !== undefined ? { runId: r.runId } : {}) }, kT, unb64(r.nA), unb64(r.nT)); } catch (e) { got = e.message; }
  if (got !== r.expect) throw new Error(`sas refusal: ${r.name}`);
}

const full = 1_000_000;
const q = Math.floor(2 ** 32 / full), rem = 2 ** 32 % full;
const bias = {
  note: 'digits = uint32 mod 10^6. 2^32 = 4294 × 10^6 + 967296, so the values 000000…967295 each come from 4295 of the 2^32 inputs and 967296…999999 from 4294.',
  quotient: q,
  remainder: rem,
  mostLikelyDigitsProbability: `${q + 1}/2^32`,
  leastLikelyDigitsProbability: `${q}/2^32`,
  relativeBias: `1/${q}`,
};

const out = {
  version: 1,
  encoding: 'base64url-nopad',
  generatedBy: 'teammate/generate.mjs, from teammate/reference.mjs (Node crypto); the test keys are the ones in vectors/v1.json',
  status: 'Checked by two implementations written separately from this one, from the spec alone, before any app or server code was built on it.',
  spec: {
    lp: 'Every hash and MAC input is a list of fields, each as a 4-byte big-endian length then the bytes, the label first. Strings are UTF-8.',
    ids: 'Account ids and run ids in these vectors are ULIDs: 26 characters of Crockford base32, upper case only, first character 0-7. The run id is a ULID by the same rule as the account ids, the format the server uses.',
    key: "K_T is the DER SubjectPublicKeyInfo of the Teammate's P-256 account key, the bytes the server gives the athlete's phone (or, on the Teammate's phone, the bytes it works out from its own share).",
    spkiSha256: 'SHA-256 of K_T, written as 43 characters of base64url without padding, in its one canonical spelling.',
    pin: {
      key: "HKDF-SHA256(ikm = the athlete's 32-byte share, salt = UTF-8 of the athlete's account id, info = 'leave:v1:teammate-pin', 32 bytes)",
      record: '{teammateAccountId, spkiSha256, compared, how, at}, exactly these five fields. compared is a boolean; how is scan or call when compared is true, and none or removed when it is false; spkiSha256 is the zero hash (43 × A, 32 zero bytes) exactly when how is removed (a tombstone: the Teammate removed); at is whole seconds since 1970, not negative, written in JSON as a plain integer (no fraction, exponent or sign: 1793570400.0 is refused). Anything else is refused as pin_record before a MAC is made or checked.',
      macInput: "LP('leave:v1:teammate-pin') LP(teammateAccountId) LP(the 32 hash bytes) LP('true' | 'false') LP(how) LP(at in decimal ASCII)",
      mac: 'HMAC-SHA256(pin key, macInput), 32 bytes, base64url; compared in constant time.',
      wrap: "On the newest pin the phone holds: a record key is wrapped to K_T only when there is a pin, its MAC verifies under this athlete's share and id, it is not a removal, and SHA-256(K_T) equals the record's spkiSha256. A removal gives teammate_removed; anything else teammate_unpinned; either way nothing is wrapped.",
      cache: "Each phone keeps the newest pin it has seen. A served pin that passes the record check and its MAC replaces the cache when there is none, or when its at is higher than the cache's, whatever Teammate it names (accepted). The identical pin changes nothing (same). Any other pin is refused as pin_older and the cache stays: the server can't clear or lower it. A record or MAC failure is pin_record or mac, the cache unchanged.",
      writeAt: "Before writing a pin (a match, sharing without comparing, a change or a removal) the phone fetches and verifies the server's current pin and counts it as seen; the new pin's at = max(now, newest seen + 1), or now when none was seen. If that fetch fails, nothing is written.",
    },
    code: {
      text: "LEAVE-TM1:<athleteAccountId>:<teammateAccountId>:<spkiSha256 of the Teammate's own key>, a plain string in a QR code, not a URL.",
      check: "In this order, the first failure deciding: format (printable ASCII with no spaces, exactly four ':'-separated fields, both ids ULIDs, the hash 43 canonical base64url characters for 32 bytes); version (the first field is exactly LEAVE-TM1); athlete (the athlete id is this phone's own account id); teammate (the Teammate id is the one the server named); key (the hash equals SHA-256 of the key this phone received, compared in constant time).",
    },
    sas: {
      roles: "A is the athlete's phone, T the Teammate's. ids = (runId, athleteAccountId, teammateAccountId), each phone using the ids it knows itself. nA and nT are 32 random bytes each; any other length is refused as sas_field.",
      commit: "c = SHA-256(LP('leave:v1:teammate-sas-commit') LP(runId) LP(athleteAccountId) LP(teammateAccountId) LP(K_T as A received it) LP(nA)), sent by A first.",
      order: "T sends nT only on a person's tap. A reveals nA only after one nT, and only once. T recomputes c with its own K_T and the revealed nA; if it differs, the comparison did not complete and no digits show.",
      digits: "d = SHA-256(LP('leave:v1:teammate-sas') LP(runId) LP(athleteAccountId) LP(teammateAccountId) LP(K_T) LP(nA) LP(nT)); digits = the first 4 bytes of d read as an unsigned big-endian 32-bit number, mod 1,000,000, written as 6 decimal digits with leading zeros, shown as 3 + 3.",
    },
  },
  keys,
  pin: { cases: pinCases, refusals: pinRefusals, wrap, jsonText, cache: cacheSteps, writeAt: writeAtCases },
  code: { encode: [{ athleteAccountId: A, teammateAccountId: TM, spki: keys.teammate.publicKeySpki, text }], check: codeChecks, receivedKeyChanged: keyChanged },
  sas: { cases: sas, notOpening: [swappedTowardAthlete, otherNonce], binding: sasBinding, lpExample, refusals: sasRefusals, bias },
};
writeFileSync(new URL('vectors/teammate-v1.json', here), `${JSON.stringify(out, null, 1)}\n`);
console.log(`vectors/teammate-v1.json: ${pinCases.length} pins, ${pinRefusals.length} pin refusals, ${wrap.length} wrap cases, ${codeChecks.length + 1} code checks, ${sas.length} SAS runs`);
