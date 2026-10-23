const RASTER_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp']);

export async function createDecryptedFile(parts, metadata = {}) {
  const meta = metadata && typeof metadata === 'object' ? metadata : {};
  // Never give sender-controlled HTML/SVG an executable same-origin Blob URL.
  const blob = new Blob(parts, { type: 'application/octet-stream' });
  const urls = [];
  const objectUrl = (value) => {
    const url = URL.createObjectURL(value);
    urls.push(url);
    return url;
  };
  const dispose = () => urls.splice(0).forEach((url) => URL.revokeObjectURL(url));
  try {
    const mime = typeof meta.mimeType === 'string' ? meta.mimeType.toLowerCase().split(';')[0].trim() : '';
    let preview = null;
    if (RASTER_TYPES.has(mime) && blob.size < 20 * 1024 * 1024 && typeof createImageBitmap === 'function') {
      let bitmap;
      try {
        bitmap = await createImageBitmap(new Blob(parts, { type: mime }));
        if (bitmap.width * bitmap.height <= 20 * 1024 * 1024) {
          const canvas = document.createElement('canvas');
          canvas.width = bitmap.width;
          canvas.height = bitmap.height;
          canvas.getContext('2d').drawImage(bitmap, 0, 0);
          const raster = await new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
          if (raster) preview = { type: 'image', src: objectUrl(raster) };
        }
      } catch {
        // Invalid/unsupported image content remains downloadable, never executable.
      } finally {
        bitmap?.close();
      }
    } else if ((mime.startsWith('text/') || mime === 'application/json') && blob.size < 2 * 1024 * 1024) {
      preview = { type: 'text', text: (await blob.text()).slice(0, 3000) };
    }
    const fileName = typeof meta.fileName === 'string'
      ? meta.fileName.replace(/[\x00-\x1f\x7f/\\]/g, '_').slice(0, 255) : '';
    return {
      fileName: fileName || 'download.bin', size: blob.size, url: objectUrl(blob),
      remark: typeof meta.remark === 'string' ? meta.remark : '', preview, dispose,
    };
  } catch (error) {
    dispose();
    throw error;
  }
}
