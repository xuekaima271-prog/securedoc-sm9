import assert from 'node:assert/strict';
import test from 'node:test';
import {
  KEY_VAULT_VERSION,
  PBKDF2_ITERATIONS,
  createEncryptedPrivateKeyRecord,
  unlockEncryptedPrivateKeyRecord,
} from '../src/crypto/key-vault.js';
import { bytesToB64 } from '../src/crypto/b64.js';

const passphrase = 'correct horse battery staple 2026';
const privateKeyPackage = bytesToB64(Uint8Array.from({ length: 128 }, (_, index) => index));
const source = {
  userId: 42,
  identity: 'alice@example.test',
  privateKeyPackage,
  createdAt: '2026-09-19T00:00:00.000Z',
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

async function wraps() {
  return createEncryptedPrivateKeyRecord(source, passphrase);
}

test('wraps and unwraps a private key without retaining plaintext in the record', async () => {
  const wrapped = await wraps();
  assert.equal(wrapped.userId, source.userId);
  assert.equal(wrapped.identity, source.identity);
  assert.equal(wrapped.privateKeyPackage, undefined);
  assert.equal(JSON.stringify(wrapped).includes(privateKeyPackage), false);
  assert.equal(wrapped.keyVault.version, KEY_VAULT_VERSION);
  assert.equal(wrapped.keyVault.iterations, PBKDF2_ITERATIONS);

  const unlocked = await unlockEncryptedPrivateKeyRecord(wrapped, source.userId, passphrase);
  assert.deepEqual(unlocked, {
    userId: source.userId,
    identity: source.identity,
    privateKeyPackage,
    createdAt: source.createdAt,
    lastUsedAt: wrapped.lastUsedAt,
  });
});

test('rejects an incorrect protection passphrase', async () => {
  const wrapped = await wraps();
  await assert.rejects(
    () => unlockEncryptedPrivateKeyRecord(wrapped, source.userId, 'wrong password that is long enough'),
    (error) => error?.code === 'KEY_VAULT_UNLOCK_FAILED',
  );
});

test('rejects tampered ciphertext and authenticated user bindings', async () => {
  const wrapped = await wraps();
  const tamperedCiphertext = clone(wrapped);
  tamperedCiphertext.keyVault.ciphertextB64 = `${tamperedCiphertext.keyVault.ciphertextB64[0] === 'A' ? 'B' : 'A'}${tamperedCiphertext.keyVault.ciphertextB64.slice(1)}`;
  await assert.rejects(
    () => unlockEncryptedPrivateKeyRecord(tamperedCiphertext, source.userId, passphrase),
    (error) => error?.code === 'KEY_VAULT_UNLOCK_FAILED',
  );

  const swappedIdentity = clone(wrapped);
  swappedIdentity.identity = 'mallory@example.test';
  await assert.rejects(
    () => unlockEncryptedPrivateKeyRecord(swappedIdentity, source.userId, passphrase),
    (error) => error?.code === 'KEY_VAULT_UNLOCK_FAILED',
  );

  const swappedUser = clone(wrapped);
  swappedUser.userId = 43;
  await assert.rejects(
    () => unlockEncryptedPrivateKeyRecord(swappedUser, 43, passphrase),
    (error) => error?.code === 'KEY_VAULT_UNLOCK_FAILED',
  );
});

test('uses fresh randomness for every encrypted envelope', async () => {
  const first = await wraps();
  const second = await wraps();
  assert.notEqual(first.keyVault.saltB64, second.keyVault.saltB64);
  assert.notEqual(first.keyVault.ivB64, second.keyVault.ivB64);
  assert.notEqual(first.keyVault.ciphertextB64, second.keyVault.ciphertextB64);
});

test('rejects malformed or downgraded encrypted records', async () => {
  const wrapped = await wraps();
  const malformedIterations = clone(wrapped);
  malformedIterations.keyVault.iterations = 1;
  await assert.rejects(
    () => unlockEncryptedPrivateKeyRecord(malformedIterations, source.userId, passphrase),
    (error) => error?.code === 'KEY_VAULT_INVALID',
  );

  const malformedCiphertext = clone(wrapped);
  malformedCiphertext.keyVault.ciphertextB64 = 'not_base64!';
  await assert.rejects(
    () => unlockEncryptedPrivateKeyRecord(malformedCiphertext, source.userId, passphrase),
    (error) => error?.code === 'KEY_VAULT_INVALID',
  );
});
