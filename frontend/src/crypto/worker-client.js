/* =============================================================================
 * 加密 Worker 客户端：惰性单例 + promise 化调用。
 * Worker 不可用（老浏览器等）时 available() 返回 false，调用方回退主线程同步路径。
 * Worker 异常/超时后单例会被销毁，下次调用自动重建新实例，避免坏实例永久假死。
 * ===========================================================================*/
let worker = null;          // null=未初始化, undefined=不可用
let seq = 0;
const pending = new Map();  // id -> {resolve, reject, onProgress, timer}

const CALL_TIMEOUT_MS = 120_000;   // 单次调用超时（大文件分块加密也应在此内完成）

/** 销毁当前 Worker 并让所有挂起请求失败；下次 getWorker() 时重建新实例。 */
function resetWorker(err) {
  const w = worker;
  worker = null;
  if (w) { try { w.terminate(); } catch { /* 已损坏的实例忽略终止失败 */ } }
  for (const [id, h] of pending) { pending.delete(id); h.reject(err); }
}

function getWorker() {
  if (worker !== null) return worker;
  try {
    worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
    worker.onmessage = (e) => {
      const { id, type } = e.data;
      const h = pending.get(id);
      if (!h) return;
      if (type === 'progress') h.onProgress?.(e.data.done, e.data.total);
      else if (type === 'done') { pending.delete(id); h.resolve(e.data.result); }
      else { pending.delete(id); h.reject(new Error(e.data.message)); }
    };
    worker.onerror = (ev) => {   // 加载/运行级错误：整单销毁重建，挂起请求全部失败，调用方回退
      resetWorker(new Error(`加密 Worker 异常${ev.message ? ': ' + ev.message : ''}`));
    };
  } catch {
    worker = undefined;
  }
  return worker;
}

export function workerAvailable() {
  return typeof Worker !== 'undefined' && !!getWorker();
}

export function callWorker(cmd, p, { transfer = [], onProgress, timeoutMs = CALL_TIMEOUT_MS } = {}) {
  const w = getWorker();
  if (!w) return Promise.reject(new Error('WORKER_UNAVAILABLE'));
  const id = ++seq;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (!pending.delete(id)) return;   // 已 settle，忽略
      // 超时的 Worker 状态未知：先 reject 本请求（文案含 Worker，调用方据此回退主线程），再整单销毁
      reject(new Error(`加密 Worker 超时（${Math.round(timeoutMs / 1000)} 秒未响应）`));
      resetWorker(new Error('加密 Worker 超时被终止'));
    }, timeoutMs);
    pending.set(id, {
      resolve: (v) => { clearTimeout(timer); resolve(v); },
      reject: (e) => { clearTimeout(timer); reject(e); },
      onProgress,
    });
    try {
      w.postMessage({ id, cmd, p }, transfer);
    } catch (e) {
      clearTimeout(timer);
      pending.delete(id);
      reject(e);
    }
  });
}
