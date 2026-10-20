// The server's part in cross-check/cross-check.sh, played by a test copy of the server's crypto
// (cross-check/server-crypto.mjs) on Node's. It knows what the real server knows: the account's
// public key, never the share. (The share is read here only to work out that public key, which
// the real server is given at sign-up.)
//
//   node cross-check/server.mjs make|check <dir>
import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, constants, privateDecrypt, randomBytes, verify } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { accountSpki, hpkeSeal } from './server-crypto.mjs';

const [phase, dir] = process.argv.slice(2);
const read = name => JSON.parse(readFileSync(join(dir, name), 'utf8'));
const b = s => Buffer.from(s, 'base64url');
const u = buf => Buffer.from(buf).toString('base64url');
const aad = (type, id) => Buffer.from(`leave:v1:${type}:${id}`);

function seal(key, plaintext, associated) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(associated);
  return Buffer.concat([nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}
function open(key, wire, associated) {
  const decipher = createDecipheriv('aes-256-gcm', key, wire.subarray(0, 12));
  decipher.setAAD(associated);
  decipher.setAuthTag(wire.subarray(wire.length - 16));
  return Buffer.concat([decipher.update(wire.subarray(12, wire.length - 16)), decipher.final()]);
}
const same = (a, b2, what) => { if (!Buffer.from(a).equals(Buffer.from(b2))) throw new Error(`server: ${what} differs`); };

const common = read('common.json');
const accountKey = accountSpki(b(common.share), common.accountId);
// The test key from the shared vectors, standing for the server's key in Google's key service.
const serverPrivateKey = createPrivateKey({ key: b(common.rsaPrivateKeyPkcs8), format: 'der', type: 'pkcs8' });

if (phase === 'make') {
  // A record the server makes (a contract's explanation): its key goes to the phones sealed to
  // the account's public key, and each phone that holds the share can open it.
  const dek = randomBytes(32), id = '01J8Z3V4Q6X7R2M9K5T0W1CRSV', info = `leave:v1:pending:contract:${id}`;
  const plaintext = Buffer.from('A record the server made, for both phones to open.');
  writeFileSync(join(dir, 'server.1.json'), JSON.stringify({
    maker: 'server',
    record: { type: 'contract', id, info, plaintext: u(plaintext), wire: u(seal(dek, plaintext, aad('contract', id))), pendingDek: u(hpkeSeal(accountKey, info, dek)) },
  }));
  console.log('server   made a record and sealed its key to the account');
} else if (phase === 'check') {
  const checked = [];
  for (const phone of ['android', 'ios']) {
    const made = read(`${phone}.1.json`);
    same(b(made.accountPublicKeySpki), accountKey, `${phone}'s account public key`);
    // The proof a phone sends to show it holds the share.
    const key = createPublicKey({ key: accountKey, format: 'der', type: 'spki' });
    if (!verify('sha256', Buffer.from(made.proof.message), { key, dsaEncoding: 'ieee-p1363' }, b(made.proof.signatureRaw))) throw new Error(`server: ${phone}'s proof does not verify`);
    // The grant: only the server's private key opens the session key, and the session key the record's.
    const sessionKey = privateDecrypt({ key: serverPrivateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, b(made.grant.sealedSessionKey));
    const granted = made.grant.records[0];
    const dek = open(sessionKey, b(granted.sealedDek), Buffer.from(`leave:v1:grant:${made.grant.sessionId}:${granted.id}`));
    same(open(dek, b(made.record.wire), aad(made.record.type, made.record.id)), b(made.record.plaintext), `${phone}'s record under its granted key`);
    checked.push(`${phone}: account key, proof, grant, record`);
    console.log(`server   verified ${phone}'s proof and opened ${phone}'s record through its grant`);
  }
  writeFileSync(join(dir, 'server.2.json'), JSON.stringify({ maker: 'server', checked }));
} else {
  throw new Error('usage: server.mjs make|check <dir>');
}
