<script setup>
// 浏览器内国密自检 + 性能基准（账本 SM9-3：浏览器实跑；SM9-6：N 次冷/热基准）。
// 测试密钥对为固定 ke 生成的自检向量（仅自检用），已在 Node 侧验证往返+双负例。
import { ref } from 'vue';
import G from '../crypto/gmssl.js';
import { createSecureDoc } from '../crypto/secure-doc.js';
import { b64ToBytes, utf8ToBytes } from '../crypto/b64.js';

const results = ref([]);
const bench = ref([]);
const running = ref(false);
const done = ref(false);

const PPUB = 'NlD9vX1H3X/QcmydttHlw095LoK+6PF0uXulc4T6SW2VOzCB+aEfSwEyRJPeRW9fXqZ0TB1Rg0cQaVFduMLHgg==';
const DE = 'FFcwiKWQtZXAqdMnrc3K9Js4JKW4TaT9N+yf18LHKm4Hfa8HkUy/SAcGlF+GFuKc3ueHWy1aNhnop+z4PwJ0U7PCwghZUbru3xR3h6qUCKlaq/A1soBFy1zMBBaCg/moClViDZQm6LGPIpoj9sBtVLoTfFTdyTz2j/Fj0Qqp2fE=';
const ID = 'selftest:corp001:1:self@test.local';

const hex = (a) => a.map((b) => b.toString(16).padStart(2, '0')).join('');
function add(name, pass, detail = '') { results.value.push({ name, pass, detail }); }
function stat(times) {
  const s = [...times].sort((a, b) => a - b);
  const avg = s.reduce((x, y) => x + y, 0) / s.length;
  return `min ${s[0].toFixed(1)}ms · avg ${avg.toFixed(1)}ms · p95 ${s[Math.floor(s.length * 0.95)].toFixed(1)}ms`;
}

async function run() {
  running.value = true; done.value = false; results.value = []; bench.value = [];
  const sdoc = createSecureDoc(G);
  await new Promise((r) => setTimeout(r, 30));   // 让 UI 先渲染
  try {
    // 1. SM3 国标向量（GB/T 32905 "abc"）
    add('SM3 国标向量("abc")',
      hex(G.sm3(utf8ToBytes('abc'))) === '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0');

    // 2. SM4 国标向量（GB/T 32907 单块）
    {
      const key = b64ToBytes('ASNFZ4mrze/+3LqYdlQyEA==');   // 0123..3210
      const k = G.sm4_key_new(); G.sm4_set_encrypt_key(k, key);
      const out = new Array(16); G.sm4_encrypt(key, 0, out, 0, k);
      add('SM4 国标向量(单块)', hex(out) === '681edf34d206965e86b3e94f536e4246');
    }

    // 3. SM4-CBC + SM3 分块加解密往返（业务路径）
    {
      const dek = sdoc.fc.genDek();
      const plain = utf8ToBytes('浏览器自检明文'.repeat(50));
      const c = sdoc.fc.encryptChunk(dek, plain);
      const back = sdoc.openChunk({ dek, ivB64: c.ivB64, ciphertext: c.ciphertext, expectDigestB64: c.digestB64 });
      add('SM4-CBC 分块加解密往返 + SM3 校验', hex(back) === hex(plain));
      let tf = false;
      try { const t = c.ciphertext.slice(); t[0] ^= 1; sdoc.openChunk({ dek, ivB64: c.ivB64, ciphertext: t, expectDigestB64: c.digestB64 }); } catch { tf = true; }
      add('负例：篡改密文分块 → SM3 拒绝', tf);
    }

    // 4. SM9 IBE 往返 + 双负例
    const ppub = sdoc.ibe.ppubFromBytes(b64ToBytes(PPUB));
    const de = sdoc.ibe.deFromBytes(b64ToBytes(DE));
    const idb = sdoc.ibe.idToBytes(ID);
    {
      const dek = sdoc.fc.genDek();
      const env = sdoc.ibe.ibeEncrypt(dek, idb, ppub);
      add('SM9 IBE 封装/解封 DEK 往返', hex(sdoc.ibe.ibeDecrypt(env, idb, de)) === hex(dek));
      let f1 = false; try { const t = env.slice(); t[t.length - 1] ^= 1; sdoc.ibe.ibeDecrypt(t, idb, de); } catch { f1 = true; }
      add('负例：篡改 SM9 密文 → MAC 拒绝', f1);
      let f2 = false; try { const w = b64ToBytes(DE); w[5] ^= 1; sdoc.ibe.ibeDecrypt(env, idb, sdoc.ibe.deFromBytes(w)); } catch { f2 = true; }
      add('负例：错误私钥 → 解封失败(身份绑定)', f2);
    }

    // 5. 性能基准（SM9-6：冷=首次(含上面自检已热身,标注)；热=N 次统计）
    await new Promise((r) => setTimeout(r, 30));
    {
      const N = 5;
      const dek = sdoc.fc.genDek();
      const encT = [], decT = [];
      let env;
      for (let i = 0; i < N; i++) {
        let t0 = performance.now(); env = sdoc.ibe.ibeEncrypt(dek, idb, ppub); encT.push(performance.now() - t0);
        t0 = performance.now(); sdoc.ibe.ibeDecrypt(env, idb, de); decT.push(performance.now() - t0);
      }
      bench.value.push({ name: `SM9 IBE 封装 ×${N}`, detail: stat(encT) });
      bench.value.push({ name: `SM9 IBE 解封 ×${N}`, detail: stat(decT) });

      const MB = 1 << 20;
      const big = new Array(MB).fill(0x5a);
      let t0 = performance.now(); const ct = sdoc.fc.sm4CbcEncrypt(dek, sdoc.fc.genIv(), big);
      const sm4ms = performance.now() - t0;
      bench.value.push({ name: 'SM4-CBC 加密 1MB', detail: `${sm4ms.toFixed(0)}ms（${(MB / 1048576 / (sm4ms / 1000)).toFixed(2)} MB/s）` });
      t0 = performance.now(); G.sm3(ct.slice(0, MB));
      const sm3ms = performance.now() - t0;
      bench.value.push({ name: 'SM3 摘要 1MB', detail: `${sm3ms.toFixed(0)}ms（${(MB / 1048576 / (sm3ms / 1000)).toFixed(2)} MB/s）` });
    }
  } catch (e) {
    add('运行异常', false, String(e));
  }
  running.value = false; done.value = true;
}
</script>

<template>
  <div class="card">
    <h2>国密自检（浏览器内实跑）</h2>
    <p>在<strong>当前浏览器</strong>中运行 SM3/SM4/SM9 正确性自检（含负例）与性能基准，证明国密算法真实运行于浏览器端。</p>
    <button :disabled="running" @click="run">{{ running ? '运行中…（SM9 配对计算较慢）' : '开始自检' }}</button>

    <table v-if="results.length" style="margin-top:1rem;">
      <thead><tr><th>检查项</th><th>结果</th></tr></thead>
      <tbody>
        <tr v-for="(r, i) in results" :key="i">
          <td>{{ r.name }}<span v-if="r.detail" class="mono"> — {{ r.detail }}</span></td>
          <td><span class="tag" :class="{ green: r.pass }">{{ r.pass ? '✅ 通过' : '❌ 失败' }}</span></td>
        </tr>
      </tbody>
    </table>

    <div v-if="bench.length" style="margin-top:1rem;">
      <h3>性能基准（本机浏览器）</h3>
      <table>
        <tbody>
          <tr v-for="(b, i) in bench" :key="i"><td>{{ b.name }}</td><td class="mono">{{ b.detail }}</td></tr>
        </tbody>
      </table>
    </div>
    <div v-if="done" class="msg" :class="results.every((r) => r.pass) ? 'ok' : 'err'">
      {{ results.every((r) => r.pass) ? `全部 ${results.length} 项自检通过` : '存在失败项' }}
    </div>
  </div>
</template>
