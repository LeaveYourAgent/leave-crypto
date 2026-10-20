// The slice of the Leave crypto contract the server's side of the cross-check needs: HPKE base mode (RFC 9180; DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM)
// with the wire format enc(65) ‖ ct ‖ tag, and the account key derived from a share by
// rejection sampling (contract section 1). Node's crypto only; checked against the
// server's own sample at the bottom of this file (`node cross-check/server-crypto.mjs`).
import { createCipheriv, createDecipheriv, createECDH, createHmac, createPrivateKey, createPublicKey, hkdfSync } from 'node:crypto';

const KEM_ID = 0x0010, KDF_ID = 0x0001, AEAD_ID = 0x0002;
const i2osp = (n, len) => { const b = Buffer.alloc(len); b.writeUIntBE(n, 0, len); return b; };
const KEM_SUITE = Buffer.concat([Buffer.from('KEM'), i2osp(KEM_ID, 2)]);
const HPKE_SUITE = Buffer.concat([Buffer.from('HPKE'), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2)]);

const extract = (salt, ikm) => createHmac('sha256', salt.length ? salt : Buffer.alloc(32)).update(ikm).digest();
function expand(prk, info, len) {
  let t = Buffer.alloc(0), out = Buffer.alloc(0);
  for (let i = 1; out.length < len; i++) { t = createHmac('sha256', prk).update(Buffer.concat([t, info, Buffer.from([i])])).digest(); out = Buffer.concat([out, t]); }
  return out.subarray(0, len);
}
const labeledExtract = (suite, salt, label, ikm) => extract(salt, Buffer.concat([Buffer.from('HPKE-v1'), suite, Buffer.from(label), ikm]));
const labeledExpand = (suite, prk, label, info, len) => expand(prk, Buffer.concat([i2osp(len, 2), Buffer.from('HPKE-v1'), suite, Buffer.from(label), info]), len);

function kemSecret(dh, enc, pkR) {
  const eaePrk = labeledExtract(KEM_SUITE, Buffer.alloc(0), 'eae_prk', dh);
  return labeledExpand(KEM_SUITE, eaePrk, 'shared_secret', Buffer.concat([enc, pkR]), 32);
}
function keySchedule(sharedSecret, info) {
  const pskIdHash = labeledExtract(HPKE_SUITE, Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0));
  const infoHash = labeledExtract(HPKE_SUITE, Buffer.alloc(0), 'info_hash', Buffer.from(info, 'utf8'));
  const context = Buffer.concat([Buffer.from([0]), pskIdHash, infoHash]);
  const secret = labeledExtract(HPKE_SUITE, sharedSecret, 'secret', Buffer.alloc(0));
  return { key: labeledExpand(HPKE_SUITE, secret, 'key', context, 32), nonce: labeledExpand(HPKE_SUITE, secret, 'base_nonce', context, 12) };
}

/** The 65-byte uncompressed point inside a P-256 SPKI DER. */
export function pointOfSpki(spkiDer) {
  const j = createPublicKey({ key: spkiDer, format: 'der', type: 'spki' }).export({ format: 'jwk' });
  return Buffer.concat([Buffer.from([4]), Buffer.from(j.x, 'base64url'), Buffer.from(j.y, 'base64url')]);
}

/** SPKI DER of the public key for a raw 32-byte P-256 scalar. */
export function spkiOfScalar(scalar) {
  const ecdh = createECDH('prime256v1'); ecdh.setPrivateKey(scalar);
  const pub = ecdh.getPublicKey();
  return createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: pub.subarray(1, 33).toString('base64url'), y: pub.subarray(33).toString('base64url') }, format: 'jwk' }).export({ format: 'der', type: 'spki' });
}

/** A node private key object for a raw scalar (for signing). */
export function privateKeyOfScalar(scalar) {
  const ecdh = createECDH('prime256v1'); ecdh.setPrivateKey(scalar);
  const pub = ecdh.getPublicKey();
  return createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: Buffer.from(scalar).toString('base64url'), x: pub.subarray(1, 33).toString('base64url'), y: pub.subarray(33).toString('base64url') }, format: 'jwk' });
}

export function hpkeSeal(recipientSpkiDer, info, plaintext) {
  const pkR = pointOfSpki(recipientSpkiDer);
  const eph = createECDH('prime256v1'); eph.generateKeys();
  const enc = eph.getPublicKey();
  const { key, nonce } = keySchedule(kemSecret(eph.computeSecret(pkR), enc, pkR), info);
  const c = createCipheriv('aes-256-gcm', key, nonce);
  return Buffer.concat([enc, c.update(plaintext), c.final(), c.getAuthTag()]);
}

export function hpkeOpen(recipientScalar, info, wire) {
  const enc = wire.subarray(0, 65), ct = wire.subarray(65, wire.length - 16), tag = wire.subarray(wire.length - 16);
  const r = createECDH('prime256v1'); r.setPrivateKey(recipientScalar);
  const { key, nonce } = keySchedule(kemSecret(r.computeSecret(enc), enc, r.getPublicKey()), info);
  const d = createDecipheriv('aes-256-gcm', key, nonce); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

const N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
/** The account's P-256 scalar from its share: HKDF candidates until one lands in [1, n-1]. */
export function accountScalar(share, accountId) {
  for (let counter = 0; counter < 256; counter++) {
    const c = Buffer.from(hkdfSync('sha256', share, Buffer.from('leave:v1:account-key'), Buffer.from(`${accountId}:${counter}`), 32));
    const v = BigInt('0x' + c.toString('hex'));
    if (v >= 1n && v < N) return c;
  }
  throw new Error('no scalar');
}
export const accountSpki = (share, accountId) => spkiOfScalar(accountScalar(share, accountId));

// Self-check against the server's own samples (2026-09-30, fixed made-up keys).
if (import.meta.url === `file://${process.argv[1]}`) {
  const share = Buffer.alloc(32, 7);
  const wire = Buffer.from('BHTHOhnXuvchtxCM9K6spEaZM2rWS9Ob8qHd0U_c010HUddCww7k9w4gpcK-KdOpIaPrq9m5yccTsSFqvyLEG4pxg6JMjyabXqyuFqIdWt-op-MTgM3ThtZ8EKrGz4PUClbPUzA2O6duoIPtJk99Las', 'base64url');
  const opened = hpkeOpen(Buffer.alloc(32, 9), 'leave:v1:device-approve:01J8Z3V4Q6X7R2M9K5T0W1Y8AR', wire);
  console.log('open service sample:', opened.equals(share) ? 'ok' : 'MISMATCH');
  const newDeviceSpki = Buffer.from('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcTX6T9k6Cdzpi79oG0v89Q58DWNU5ir7C_8qNClheGXtTB8C3bkCPuVqVX5RXWqdxmwR8iCWDeWUM031iHdnJA', 'base64url');
  console.log('spki of scalar 0x09:', spkiOfScalar(Buffer.alloc(32, 9)).equals(newDeviceSpki) ? 'ok' : 'MISMATCH');
  const round = hpkeOpen(Buffer.alloc(32, 9), 'info', hpkeSeal(newDeviceSpki, 'info', share));
  console.log('seal then open:', round.equals(share) ? 'ok' : 'MISMATCH', '· wire', hpkeSeal(newDeviceSpki, 'info', share).length, 'bytes');
  const acct = accountSpki(share, '01J8Z3V4Q6X7R2M9K5T0W1Y8AC').toString('base64url');
  console.log('account key from share:', acct === 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbY70BkaLyVRMTM8AMERMJEthHFm85FuJ9vcthMhLdhgI6gDr5vO2p_A-RxSE2Y_DlqB7XRDUdSgqOofwlTXmwg' ? 'ok' : 'MISMATCH');
}
