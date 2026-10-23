import {
  KeyVaultError,
  classifyPrivateKeyRecord,
  createEncryptedPrivateKeyRecord,
  unlockEncryptedPrivateKeyRecord,
} from '../crypto/key-vault.js';

// IndexedDB 仅保存经本地保护口令加密的 SM9 私钥包。
const DB_NAME = 'securedoc';
const STORE = 'sm9keys';
const VERSION = 1;

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: 'userId' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function getRecord(userId) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const request = tx.objectStore(STORE).get(userId);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

async function putRecord(rec) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(rec);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** 保存：{userId, identity, privateKeyPackage, createdAt}，仅写入加密信封。 */
export async function savePrivateKey(rec, passphrase) {
  const encryptedRecord = await createEncryptedPrivateKeyRecord(rec, passphrase);
  await putRecord(encryptedRecord);
}

export async function hasPrivateKey(userId) {
  return (await getPrivateKeyState(userId)) !== 'missing';
}

/** 返回 missing / legacy / encrypted，供界面决定是否提示迁移。 */
export async function getPrivateKeyState(userId) {
  return classifyPrivateKeyRecord(await getRecord(userId));
}

export async function loadPrivateKey(userId, passphrase) {
  const record = await getRecord(userId);
  const state = classifyPrivateKeyRecord(record);
  if (state === 'missing') {
    throw new KeyVaultError('KEY_VAULT_MISSING', '本机没有已加密保存的 SM9 私钥，请先在「我的密钥」页面初始化。');
  }
  if (state === 'legacy') {
    throw new KeyVaultError('KEY_VAULT_LEGACY', '检测到旧版未加密私钥，请先在「我的密钥」页面完成本地加密迁移。');
  }
  return unlockEncryptedPrivateKeyRecord(record, userId, passphrase);
}

/** 将旧版明文记录单次 put 覆盖为加密记录；加密失败时旧记录保持原样。 */
export async function protectLegacyPrivateKey(userId, passphrase) {
  const record = await getRecord(userId);
  const state = classifyPrivateKeyRecord(record);
  if (state === 'missing') {
    throw new KeyVaultError('KEY_VAULT_MISSING', '本机没有可迁移的 SM9 私钥。');
  }
  if (state !== 'legacy') {
    throw new KeyVaultError('KEY_VAULT_ALREADY_ENCRYPTED', '本机私钥已经受到本地保护口令加密。');
  }
  const encryptedRecord = await createEncryptedPrivateKeyRecord(record, passphrase);
  await putRecord(encryptedRecord);
}

export async function clearPrivateKey(userId) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(userId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
