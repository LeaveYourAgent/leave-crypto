import { NativeModules } from 'react-native';
import { tokenStore } from './tokens';

/**
 * Typed surface of the native LeaveCrypto module (ios/app-bridge/LeaveCrypto.swift). The
 * share and every data key stay in native memory or the Keychain; JavaScript only ever
 * handles wrapped keys, ciphertext and file paths. Binary values are base64url without
 * padding, as everywhere in the API.
 */

export type RecordType = 'strand' | 'contract' | 'contractField' | 'contractMarks' | 'file' | 'embedding' | 'thread' | 'pitch' | 'receipt' | 'export';

type NativeCrypto = {
  useAccount?(accountId: string | null): Promise<boolean>;
  adoptLegacyShare?(accountId: string, publicKey: string): Promise<boolean>;
  ensureShare(): Promise<{ created: boolean }>;
  hasShare(): Promise<boolean>;
  accountProof(accountId: string, message: string): Promise<string>;
  wrapShareTo(recipientSpki: string, info: string): Promise<string>;
  acceptShare(wire: string, info: string, reason: string, accountId: string, publicKey: string): Promise<boolean>;
  accountPublicKey(accountId: string): Promise<string>;
  newRecordKey(type: RecordType, id: string): Promise<{ shareWrappedDek: string }>;
  importShareWrappedDek(type: RecordType, id: string, wire: string): Promise<boolean>;
  importPendingDek(type: RecordType, id: string, wire: string, info: string, accountId: string): Promise<{ shareWrappedDek: string }>;
  wrapDekTo(type: RecordType, id: string, recipientSpki: string, info: string): Promise<string>;
  encrypt(type: RecordType, id: string, plaintext: string): Promise<string>;
  decrypt(type: RecordType, id: string, wire: string): Promise<string>;
  encryptFile(type: RecordType, id: string, srcPath: string, dstPath: string): Promise<{ sha256: string; sizeBytes: number }>;
  decryptFile(type: RecordType, id: string, srcPath: string, dstPath: string): Promise<{ sizeBytes: number }>;
  openExport(zipPath: string, dstPath: string, folder: string, keyTypes: Record<string, string>): Promise<{ opened: number; unopened: number }>;
  grant(sessionId: string, serverSpki: string, exp: number, records: { id: string; type: RecordType }[]): Promise<{ body: string; header: string }>;
  aliasKey(fromType: RecordType, fromId: string, toType: RecordType, toId: string): Promise<boolean>;
  hasKey(type: RecordType, id: string): Promise<boolean>;
  compareCode?(key: string, requestId: string): Promise<string>;
  forgetKeys(): Promise<boolean>;
  deleteShare(): Promise<boolean>;
};

const native = NativeModules.LeaveCrypto as NativeCrypto | undefined;

function must(): NativeCrypto {
  if (!native) {
    throw new Error('This build has no crypto module.');
  }
  return native;
}

/**
 * The share lives in a Keychain slot named by the Leave account: one slot per Apple Account let one account's key replace another's on every device
 * the item syncs to. The native module is told which account is signed in before anything
 * that reads the share; `using` is what it was last told in this run of JavaScript.
 */
let using: string | null | undefined;
async function forAccount(): Promise<NativeCrypto> {
  const n = must();
  const id = (await tokenStore.get())?.accountId ?? null;
  if (id !== using) {
    await n.useAccount?.(id);
    using = id;
  }
  return n;
}

export const crypto = {
  available: () => !!native,
  /** Creates the share. Only the first phone on an account calls this (see identity.ts). */
  ensureShare: async () => (await forAccount()).ensureShare(),
  hasShare: async () => (await forAccount()).hasShare(),
  /**
   * The one-time move from the slot every account used to share: copied into this account's
   * slot only when it is this account's key. The old item is never deleted.
   */
  adoptLegacyShare: async (accountId: string, publicKey: string) => (await (await forAccount()).adoptLegacyShare?.(accountId, publicKey)) ?? false,
  /** The account key's signature over `message` (raw r‖s, base64url): proof this phone holds the share. */
  accountProof: async (accountId: string, message: string) => (await forAccount()).accountProof(accountId, message),
  /** The share, HPKE-wrapped to another phone's agreement key (device approval). */
  wrapShareTo: async (recipientSpki: string, info: string) => (await forAccount()).wrapShareTo(recipientSpki, info),
  /**
   * Take the share an approving phone wrapped to this one; it goes straight to the Keychain,
   * and only if it is this account's key (`publicKey`, as the server holds it).
   */
  acceptShare: async (wire: string, info: string, reason: string, accountId: string, publicKey: string) =>
    (await forAccount()).acceptShare(wire, info, reason, accountId, publicKey),
  accountPublicKey: async (accountId: string) => (await forAccount()).accountPublicKey(accountId),
  newRecordKey: async (type: RecordType, id: string) => (await forAccount()).newRecordKey(type, id),
  importShareWrappedDek: async (type: RecordType, id: string, wire: string) => (await forAccount()).importShareWrappedDek(type, id, wire),
  importPendingDek: async (type: RecordType, id: string, wire: string, info: string, accountId: string) =>
    (await forAccount()).importPendingDek(type, id, wire, info, accountId),
  wrapDekTo: (type: RecordType, id: string, recipientSpki: string, info: string) => must().wrapDekTo(type, id, recipientSpki, info),
  encrypt: (type: RecordType, id: string, plaintext: string) => must().encrypt(type, id, plaintext),
  decrypt: (type: RecordType, id: string, wire: string) => must().decrypt(type, id, wire),
  encryptFile: (type: RecordType, id: string, srcPath: string, dstPath: string) => must().encryptFile(type, id, srcPath, dstPath),
  decryptFile: (type: RecordType, id: string, srcPath: string, dstPath: string) => must().decryptFile(type, id, srcPath, dstPath),
  /** The export archive opened into a plain zip with the keys already imported (the app's export code, not in this repository). */
  openExport: (zipPath: string, dstPath: string, folder: string, keyTypes: Record<string, string>) => must().openExport(zipPath, dstPath, folder, keyTypes),
  grant: (sessionId: string, serverSpki: string, exp: number, records: { id: string; type: RecordType }[]) => must().grant(sessionId, serverSpki, exp, records),
  /** The same DEK under another record name (Markdown upload, contractField). */
  aliasKey: (fromType: RecordType, fromId: string, toType: RecordType, toId: string) => must().aliasKey(fromType, fromId, toType, toId),
  hasKey: (type: RecordType, id: string) => must().hasKey(type, id),
  /**
   * The six digits both phones show when a new phone asks for the key: worked out from
   * the new phone's own key and the request's id, natively. Null when it can't be worked out.
   */
  compareCode: async (key: string, requestId: string): Promise<string | null> => (await native?.compareCode?.(key, requestId).catch(() => null)) ?? null,
  forgetKeys: () => must().forgetKeys(),
  deleteShare: async () => (await forAccount()).deleteShare(),
};
