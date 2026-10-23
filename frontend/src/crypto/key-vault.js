import { b64ToBytes, bytesToB64 } from './b64.js';

export const KEY_VAULT_VERSION = 1;
export const PBKDF2_ITERATIONS = 600000;
export const MIN_PASSPHRASE_LENGTH = 12;

const SALT_BYTES = 16;
const IV_BYTES = 12;
const MAX_PASSPHRASE_LENGTH = 1024;
const MAX_USER_ID_LENGTH = 128;
const MAX_IDENTITY_LENGTH = 512;
const MAX_TIMESTAMP_LENGTH = 64;
const MAX_PRIVATE_KEY_BYTES = 4096;
const MAX_CIPHERTEXT_BYTES = MAX_PRIVATE_KEY_BYTES + 1024;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const encoder = new TextEncoder();

export class KeyVaultError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'KeyVaultError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new KeyVaultError(code, message);
}

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function rejectUnexpectedKeys(value, allowed, label) {
  const keys = Object.keys(value);
  if (keys.length > allowed.length || keys.some((key) => !allowed.includes(key))) {
    fail('KEY_VAULT_INVALID', `${label} 包含不支持的字段。`);
  }
}

function normalizeUserId(userId) {
  if (typeof userId === 'number' && Number.isSafeInteger(userId) && userId >= 0) return String(userId);
  if (typeof userId === 'string' && userId.length <= MAX_USER_ID_LENGTH && userId.trim()) return userId;
  fail('KEY_VAULT_INVALID', '本地密钥记录的用户标识无效。');
}

function requireText(value, label, maxLength) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    fail('KEY_VAULT_INVALID', `${label} 无效或超出长度限制。`);
  }
  return value;
}

function optionalTimestamp(value, label) {
  if (value === undefined || value === null) return null;
  return requireText(value, label, MAX_TIMESTAMP_LENGTH);
}

function requirePassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LENGTH || passphrase.length > MAX_PASSPHRASE_LENGTH) {
    fail('KEY_VAULT_PASSPHRASE_INVALID', `本地保护口令须为 ${MIN_PASSPHRASE_LENGTH}-${MAX_PASSPHRASE_LENGTH} 个字符。`);
  }
}

function decodeBase64(value, label, minBytes, maxBytes) {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(maxBytes / 3) * 4 || !BASE64.test(value)) {
    fail('KEY_VAULT_INVALID', `${label} 格式无效。`);
  }
  const bytes = new Uint8Array(b64ToBytes(value));
  if (bytes.length < minBytes || bytes.length > maxBytes || bytesToB64(bytes) !== value) {
    bytes.fill(0);
    fail('KEY_VAULT_INVALID', `${label} 长度无效。`);
  }
  return bytes;
}

function validatePrivateKeyPackage(value) {
  const bytes = decodeBase64(value, '私钥包', 1, MAX_PRIVATE_KEY_BYTES);
  bytes.fill(0);
  return value;
}

function validatePlainRecord(record) {
  if (!isObject(record)) fail('KEY_VAULT_INVALID', '待保存的私钥记录无效。');
  rejectUnexpectedKeys(record, ['userId', 'identity', 'privateKeyPackage', 'createdAt', 'lastUsedAt'], '待保存的私钥记录');
  const userIdText = normalizeUserId(record.userId);
  const identity = requireText(record.identity, 'SM9 身份标识', MAX_IDENTITY_LENGTH);
  const privateKeyPackage = validatePrivateKeyPackage(record.privateKeyPackage);
  return {
    userId: record.userId,
    userIdText,
    identity,
    privateKeyPackage,
    createdAt: optionalTimestamp(record.createdAt, '创建时间'),
    lastUsedAt: optionalTimestamp(record.lastUsedAt, '最后使用时间'),
  };
}

function validateEncryptedRecord(record) {
  if (!isObject(record) || hasOwn(record, 'privateKeyPackage')) {
    fail('KEY_VAULT_INVALID', '本地加密私钥记录无效。');
  }
  rejectUnexpectedKeys(record, ['userId', 'identity', 'createdAt', 'lastUsedAt', 'keyVault'], '本地加密私钥记录');
  const userIdText = normalizeUserId(record.userId);
  const identity = requireText(record.identity, 'SM9 身份标识', MAX_IDENTITY_LENGTH);
  if (!isObject(record.keyVault)) fail('KEY_VAULT_INVALID', '本地密钥保护信封缺失。');
  return {
    userId: record.userId,
    userIdText,
    identity,
    createdAt: optionalTimestamp(record.createdAt, '创建时间'),
    lastUsedAt: optionalTimestamp(record.lastUsedAt, '最后使用时间'),
    keyVault: validateEnvelope(record.keyVault),
  };
}

function validateEnvelope(envelope) {
  rejectUnexpectedKeys(envelope, ['version', 'kdf', 'iterations', 'cipher', 'saltB64', 'ivB64', 'ciphertextB64'], '本地密钥保护信封');
  if (envelope.version !== KEY_VAULT_VERSION
    || envelope.kdf !== 'PBKDF2-SHA-256'
    || envelope.iterations !== PBKDF2_ITERATIONS
    || envelope.cipher !== 'AES-256-GCM') {
    fail('KEY_VAULT_INVALID', '本地密钥保护信封的算法参数不受支持。');
  }
  const salt = decodeBase64(envelope.saltB64, 'PBKDF2 盐值', SALT_BYTES, SALT_BYTES);
  const iv = decodeBase64(envelope.ivB64, 'AES-GCM 初始向量', IV_BYTES, IV_BYTES);
  const ciphertext = decodeBase64(envelope.ciphertextB64, '加密私钥包', 17, MAX_CIPHERTEXT_BYTES);
  return { ...envelope, salt, iv, ciphertext };
}

function getWebCrypto() {
  const webCrypto = globalThis.crypto;
  if (!webCrypto?.subtle || typeof webCrypto.getRandomValues !== 'function') {
    fail('KEY_VAULT_WEBCRYPTO_UNAVAILABLE', '当前浏览器不支持 Web Crypto，无法保护本地私钥。');
  }
  return webCrypto;
}

function aad(userIdText, identity) {
  return encoder.encode(JSON.stringify({ version: KEY_VAULT_VERSION, userId: userIdText, identity }));
}

async function deriveAesKey(webCrypto, passphraseBytes, salt) {
  const baseKey = await webCrypto.subtle.importKey('raw', passphraseBytes, 'PBKDF2', false, ['deriveKey']);
  return webCrypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function parsePayload(bytes, metadata) {
  let payload;
  try {
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail('KEY_VAULT_UNLOCK_FAILED', '本地保护口令不正确或私钥包已损坏。');
  }
  if (!isObject(payload)) fail('KEY_VAULT_UNLOCK_FAILED', '本地保护口令不正确或私钥包已损坏。');
  rejectUnexpectedKeys(payload, ['version', 'userId', 'identity', 'privateKeyPackage'], '解密后的私钥包');
  if (payload.version !== KEY_VAULT_VERSION
    || payload.userId !== metadata.userIdText
    || payload.identity !== metadata.identity) {
    fail('KEY_VAULT_UNLOCK_FAILED', '本地保护口令不正确或私钥包已损坏。');
  }
  try {
    return validatePrivateKeyPackage(payload.privateKeyPackage);
  } catch {
    fail('KEY_VAULT_UNLOCK_FAILED', '本地保护口令不正确或私钥包已损坏。');
  }
}

export function classifyPrivateKeyRecord(record) {
  if (record === null || record === undefined) return 'missing';
  return isObject(record) && hasOwn(record, 'privateKeyPackage') ? 'legacy' : 'encrypted';
}

export async function createEncryptedPrivateKeyRecord(record, passphrase) {
  const metadata = validatePlainRecord(record);
  requirePassphrase(passphrase);
  const webCrypto = getWebCrypto();
  const passphraseBytes = encoder.encode(passphrase);
  const payloadBytes = encoder.encode(JSON.stringify({
    version: KEY_VAULT_VERSION,
    userId: metadata.userIdText,
    identity: metadata.identity,
    privateKeyPackage: metadata.privateKeyPackage,
  }));
  const salt = new Uint8Array(SALT_BYTES);
  const iv = new Uint8Array(IV_BYTES);
  webCrypto.getRandomValues(salt);
  webCrypto.getRandomValues(iv);

  try {
    const key = await deriveAesKey(webCrypto, passphraseBytes, salt);
    const encrypted = new Uint8Array(await webCrypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad(metadata.userIdText, metadata.identity), tagLength: 128 },
      key,
      payloadBytes,
    ));
    const now = new Date().toISOString();
    return {
      userId: metadata.userId,
      identity: metadata.identity,
      createdAt: metadata.createdAt || now,
      lastUsedAt: metadata.lastUsedAt || now,
      keyVault: {
        version: KEY_VAULT_VERSION,
        kdf: 'PBKDF2-SHA-256',
        iterations: PBKDF2_ITERATIONS,
        cipher: 'AES-256-GCM',
        saltB64: bytesToB64(salt),
        ivB64: bytesToB64(iv),
        ciphertextB64: bytesToB64(encrypted),
      },
    };
  } finally {
    passphraseBytes.fill(0);
    payloadBytes.fill(0);
  }
}

export async function unlockEncryptedPrivateKeyRecord(record, expectedUserId, passphrase) {
  const metadata = validateEncryptedRecord(record);
  if (normalizeUserId(expectedUserId) !== metadata.userIdText) {
    fail('KEY_VAULT_BINDING_MISMATCH', '本地私钥不属于当前登录用户。');
  }
  requirePassphrase(passphrase);
  const webCrypto = getWebCrypto();
  const passphraseBytes = encoder.encode(passphrase);
  let plaintext = null;
  try {
    const key = await deriveAesKey(webCrypto, passphraseBytes, metadata.keyVault.salt);
    plaintext = new Uint8Array(await webCrypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: metadata.keyVault.iv,
        additionalData: aad(metadata.userIdText, metadata.identity),
        tagLength: 128,
      },
      key,
      metadata.keyVault.ciphertext,
    ));
    const privateKeyPackage = parsePayload(plaintext, metadata);
    return {
      userId: metadata.userId,
      identity: metadata.identity,
      privateKeyPackage,
      createdAt: metadata.createdAt,
      lastUsedAt: metadata.lastUsedAt,
    };
  } catch (error) {
    if (error instanceof KeyVaultError) throw error;
    throw new KeyVaultError('KEY_VAULT_UNLOCK_FAILED', '本地保护口令不正确或私钥包已损坏。');
  } finally {
    passphraseBytes.fill(0);
    plaintext?.fill(0);
    metadata.keyVault.salt.fill(0);
    metadata.keyVault.iv.fill(0);
    metadata.keyVault.ciphertext.fill(0);
  }
}
