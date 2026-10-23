import test from 'node:test';
import assert from 'node:assert/strict';
import { createDecryptedFile } from '../src/utils/decrypted-file.js';

test('HTML is rendered as text and its download URL is non-executable', async () => {
  const html = '<script>window.leaked = true</script>';
  const file = await createDecryptedFile([html], { mimeType: 'text/html', fileName: 'payload.html' });
  try {
    assert.deepEqual(file.preview, { type: 'text', text: html });
    const response = await fetch(file.url);
    assert.equal(response.headers.get('content-type'), 'application/octet-stream');
    assert.equal(await response.text(), html);
  } finally { file.dispose(); }
  await assert.rejects(fetch(file.url));
});

test('SVG and unknown MIME types never get an active preview', async () => {
  for (const mimeType of ['image/svg+xml', 'application/xhtml+xml', 'application/pdf', 'image/not-real']) {
    const file = await createDecryptedFile(['<svg onload="alert(1)"/>'], { mimeType });
    assert.equal(file.preview, null);
    assert.equal((await fetch(file.url)).headers.get('content-type'), 'application/octet-stream');
    file.dispose();
  }
});

test('invalid metadata and large text do not break downloads or enable previews', async () => {
  const fallback = await createDecryptedFile(['content'], null);
  assert.equal(fallback.fileName, 'download.bin');
  fallback.dispose();
  const large = await createDecryptedFile([new Uint8Array(2 * 1024 * 1024)], {
    mimeType: 'text/html', fileName: '../payload\u0000.html', remark: {},
  });
  assert.equal(large.preview, null);
  assert.equal(large.fileName.includes('/'), false);
  assert.equal(large.fileName.includes('\u0000'), false);
  assert.equal(large.remark, '');
  large.dispose();
});
