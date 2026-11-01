// Holds teammate/reference.mjs to vectors/teammate-v1.json, case by case (`node teammate/check.mjs`).
// Exits 1 on the first case that differs.
import { readFileSync } from 'node:fs';
import * as T from './reference.mjs';

const v = JSON.parse(readFileSync(new URL('../vectors/teammate-v1.json', import.meta.url), 'utf8'));
const unb64 = s => Buffer.from(s, 'base64url');
const b64 = b => Buffer.from(b).toString('base64url');
let n = 0;
const eq = (name, got, want) => {
  n++;
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.error(`✗ ${name}\n  got  ${JSON.stringify(got)}\n  want ${JSON.stringify(want)}`);
    process.exit(1);
  }
};

const { athlete, teammate } = v.keys;
const share = unb64(athlete.share), A = athlete.accountId, TM = teammate.accountId;

for (const c of v.pin.cases) {
  eq(`pin macInput: ${c.name}`, b64(T.pinMacInput(c.record)), c.macInput);
  eq(`pin mac: ${c.name}`, b64(T.pinMac(share, A, c.record)), c.mac);
  eq(`pin verifies: ${c.name}`, T.verifyPin(share, A, c.record, c.mac), true);
}
for (const r of v.pin.refusals) {
  const got = T.pinRecordProblem(r.record) ? 'pin_record' : T.verifyPin(share, A, r.record, r.mac) ? null : 'mac';
  eq(`pin refused: ${r.name}`, got, r.expect);
}
for (const w of v.pin.wrap) eq(`wrap: ${w.name}`, T.wrapRefusal(share, A, w.pin, unb64(w.spki)), w.expect);

for (const e of v.code.encode) eq('code text', T.teammateCode(e.athleteAccountId, e.teammateAccountId, unb64(e.spki)), e.text);
for (const c of v.code.check) {
  const r = T.checkTeammateCode(c.text, A, TM, unb64(teammate.publicKeySpki));
  eq(`code check: ${c.name}`, r.ok ? 'ok' : r.reason, c.expect);
}
{
  const c = v.code.receivedKeyChanged;
  const r = T.checkTeammateCode(c.text, A, TM, unb64(c.receivedSpki));
  eq(`code check: ${c.name}`, r.ok ? 'ok' : r.reason, c.expect);
}

const idsOf = s => ({ runId: s.runId, athleteAccountId: s.athleteAccountId, teammateAccountId: s.teammateAccountId });
for (const s of v.sas.cases) {
  const ids = idsOf(s), nA = unb64(s.nA), nT = unb64(s.nT);
  eq(`sas commit: ${s.name}`, b64(T.sasCommit(ids, unb64(s.spkiAsAthleteReceived), nA)), s.commitment);
  eq(`sas opens: ${s.name}`, T.sasOpens(ids, unb64(s.teammateOwnSpki), nA, unb64(s.commitment)), s.opens);
  const num = T.sasNumber(ids, unb64(s.teammateOwnSpki), nA, nT);
  eq(`sas number: ${s.name}`, [num.uint32, num.digits, T.sasLine(num.digits)], [s.uint32, s.digits, s.line]);
  eq(`sas digits = uint32 mod 10^6: ${s.name}`, String(s.uint32 % 1_000_000).padStart(6, '0'), s.digits);
}
for (const s of v.sas.notOpening) eq(`sas does not open: ${s.name}`, T.sasOpens(idsOf(s), unb64(s.teammateOwnSpki), unb64(s.nA), unb64(s.commitment)), s.opens);
for (const s of v.sas.binding) {
  const ids = idsOf(s);
  eq(`sas binding commit: ${s.name}`, b64(T.sasCommit(ids, unb64(teammate.publicKeySpki), unb64(s.nA))), s.commitment);
  eq(`sas binding digits: ${s.name}`, T.sasNumber(ids, unb64(teammate.publicKeySpki), unb64(s.nA), unb64(s.nT)).digits, s.digits);
}
eq('lp first', T.fields(...v.sas.lpExample.first.fields).toString('hex'), v.sas.lpExample.first.hex);
eq('lp second', T.fields(...v.sas.lpExample.second.fields).toString('hex'), v.sas.lpExample.second.hex);
const base = v.sas.cases[0];
for (const r of v.sas.refusals) {
  let got = null;
  try {
    T.sasNumber({ ...idsOf(base), ...(r.runId !== undefined ? { runId: r.runId } : {}) }, unb64(teammate.publicKeySpki), unb64(r.nA), unb64(r.nT));
  } catch (e) {
    got = e.message;
  }
  eq(`sas refused: ${r.name}`, got, r.expect);
}
eq('bias', [v.sas.bias.quotient, v.sas.bias.remainder], [Math.floor(2 ** 32 / 1e6), 2 ** 32 % 1e6]);
console.log(`✓ vectors/teammate-v1.json: ${n} checks`);
