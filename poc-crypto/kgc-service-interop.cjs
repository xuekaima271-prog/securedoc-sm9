/* =============================================================================
 * Step 9 闸门：真 KGC 服务(:8081) ↔ 浏览器 JS(guanzhi 真配对) 端到端互通实证
 *
 * 与 sm9-interop.cjs(PoC CLI 互通) 的区别：这里打的是【运行中的 Spring Boot KGC 服务】
 *  1) GET  /kgc/sm9/master-public-key            → 取主公钥 Ppub_e（64B）
 *  2) POST /kgc/sm9/issue-private-key (带令牌)    → 取 Bob/Alice 的私钥包 de（128B）
 *  3) 用服务返回的【主公钥】对 Bob 身份 IBE 封装随机 DEK
 *  4) 用服务签发的【Bob 私钥】解封 → 还原 DEK            （主链路：真服务↔JS 互通）
 *  5) 用【Alice 私钥】解 Bob 的密文 → 必须失败            （身份绑定）
 *  6) 篡改密文 → 必须失败                                  （防篡改）
 *
 * 服务的主私钥 ke 是保密随机生成的（KGC 不外泄），故此处不做 de 的逐字节对标
 * （那需要共享固定 ke，已在 kgc-service 的 Sm9CoreTest 用已知 ke 锁死）；
 * 这里证明的是更强的端到端性质：服务的 Ppub_e 与 de 是一对可被浏览器 JS 正常使用的 SM9 密钥。
 * ===========================================================================*/
const fs = require('fs');
const path = require('path');
const { randomBytes } = require('crypto');

const dir = path.join(__dirname, 'gmssljs');
const libCode = fs.readFileSync(path.join(dir, 'sm3.js'), 'utf8') + '\n'
              + fs.readFileSync(path.join(dir, 'sm9.js'), 'utf8') + '\n'
              + ';globalThis.__sm9 = { SM9_N, SM9_P2 };';
eval(libCode);
const { SM9_N, SM9_P2 } = globalThis.__sm9;
const N = SM9_N, HID_ENC = 0x03;

const BASE = process.env.KGC_BASE || 'http://localhost:8081';
const TOKEN = process.env.KGC_SERVICE_TOKEN || 'dev-kgc-token-change-me';

// ---- 工具（与 sm9-interop.cjs 一致）----
const u32be = (x) => [(x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255];
const bytesToBig = (a) => a.reduce((acc, b) => (acc << 8n) + BigInt(b), 0n);
function bigTo32(x){ const o=new Array(32); for(let i=31;i>=0;i--){o[i]=Number(x&255n);x>>=8n;} return o; }
const xorBytes = (a,b)=>a.map((x,i)=>x^b[i]);
function kdf(Z,kl){ let o=[],ct=1; while(o.length<kl){o=o.concat(sm3([...Z,...u32be(ct)]));ct++;} return o.slice(0,kl); }
const mac=(K2,C2)=>sm3([...C2,...K2]);
function funcH(prefix,Z,n){ const nb=n.toString(2).length, hl=Math.ceil((5*nb)/32); let Ha=[],ct=1;
  while(Ha.length<hl){Ha=Ha.concat(sm3([prefix,...Z,...u32be(ct)]));ct++;} return (bytesToBig(Ha.slice(0,hl))%(n-1n))+1n; }
const H1=(id,hid)=>funcH(0x01,[...id,hid],N);
const idToBytes=(s)=>[...Buffer.from(s,'utf8')];
function g1Affine(P){ const a=point_new(); point_get_affine(a,P); return a; }
function g1ToBytes(P){ const a=g1Affine(P); return [...bigTo32(a.X),...bigTo32(a.Y)]; }
function fp12ToBytes(f){ const o=[]; for(const fp4 of f) for(const fp2 of fp4) for(const c of fp2) o.push(...bigTo32(c)); return o; }

// ---- IBE 加解密（与 sm9-ibe-test / sm9-interop 一致）----
function ibeEncrypt(M, idBytes, Ppub){
  const h1=H1(idBytes,HID_ENC);
  const t=point_new(); point_mul_G(t,h1);
  const QB=point_new(); point_add(QB,t,Ppub);
  const QBa=g1Affine(QB);   // 关键修复：point_mul 要求仿射基点，否则 C1 错→e(de,C1)≠g^r
  const g=fp12_new(); sm9_pairing(g,SM9_P2,Ppub);
  for(;;){ const r=(bytesToBig([...randomBytes(40)])%N)||1n;
    const C1=point_new(); point_mul(C1,r,QBa); const C1a=g1Affine(C1);
    const w=fp12_new(); fp12_pow(w,g,r);
    const Z=[...g1ToBytes(C1a),...fp12ToBytes(w),...idBytes];
    const K=kdf(Z,M.length+32), K1=K.slice(0,M.length), K2=K.slice(M.length);
    if(K1.every(x=>x===0)) continue;
    return [...g1ToBytes(C1a),...mac(K2,xorBytes(M,K1)),...xorBytes(M,K1)];
  }
}
function ibeDecrypt(ct, idBytes, de){
  const C1={X:bytesToBig(ct.slice(0,32)),Y:bytesToBig(ct.slice(32,64)),Z:1n};
  const C3=ct.slice(64,96), C2=ct.slice(96);
  const w=fp12_new(); sm9_pairing(w,de,C1);
  const Z=[...ct.slice(0,64),...fp12ToBytes(w),...idBytes];
  const K=kdf(Z,C2.length+32), K1=K.slice(0,C2.length), K2=K.slice(C2.length);
  const M=xorBytes(C2,K1);
  if(mac(K2,C2).join(',')!==C3.join(',')) throw new Error('MAC 失败');
  return M;
}

// ---- 解析服务返回 ----
function ppubFromBytes(b){ return { X:bytesToBig(b.slice(0,32)), Y:bytesToBig(b.slice(32,64)), Z:1n }; }
function deFromBytes(b){ return {
  X:[bytesToBig(b.slice(0,32)),  bytesToBig(b.slice(32,64))],
  Y:[bytesToBig(b.slice(64,96)), bytesToBig(b.slice(96,128))], Z:[1n,0n] }; }

async function getMasterPublicKey(){
  const r = await fetch(`${BASE}/kgc/sm9/master-public-key`);
  const j = await r.json();
  return [...Buffer.from(j.data.masterPublicKey, 'base64')];
}
async function issue(userId, identity){
  const r = await fetch(`${BASE}/kgc/sm9/issue-private-key`, {
    method:'POST',
    headers:{ 'Content-Type':'application/json', 'X-KGC-Token': TOKEN },
    body: JSON.stringify({ userId, identity, deviceFingerprint:'interop-test' }) });
  const j = await r.json();
  if(!j.success) throw new Error('签发失败: '+JSON.stringify(j));
  return [...Buffer.from(j.data.privateKeyPackage, 'base64')];
}

// =============================== 主流程 ===============================
const hex=(a)=>a.map(b=>b.toString(16).padStart(2,'0')).join('');
let pass=0,fail=0; const ok=(n,c,e='')=>{c?(pass++,console.log('  ✅',n)):(fail++,console.log('  ❌',n));if(e)console.log('     ',e);};

(async () => {
  console.log('\n======== Step9：真 KGC 服务 ↔ JS 端到端互通实证 ========');
  console.log('  · KGC =', BASE);

  const ID_BOB   = idToBytes('user:corp001:10002:bob@example.com');
  const ID_ALICE = idToBytes('user:corp001:10001:alice@example.com');

  const pubBytes = await getMasterPublicKey();
  ok('GET 主公钥成功（64 字节）', pubBytes.length===64);
  const Ppub = ppubFromBytes(pubBytes);

  const deBobBytes   = await issue(10002, 'user:corp001:10002:bob@example.com');
  const deAliceBytes = await issue(10001, 'user:corp001:10001:alice@example.com');
  ok('POST 签发 Bob 私钥成功（128 字节）', deBobBytes.length===128);
  ok('POST 签发 Alice 私钥成功（128 字节）', deAliceBytes.length===128);
  const deBob = deFromBytes(deBobBytes), deAlice = deFromBytes(deAliceBytes);

  // 主链路：服务主公钥封装 + 服务签发的 Bob 私钥解封
  const DEK = [...randomBytes(16)];
  const env = ibeEncrypt(DEK, ID_BOB, Ppub);
  const back = ibeDecrypt(env, ID_BOB, deBob);
  ok('服务主公钥封装 DEK + Bob 服务私钥解封 → 还原 DEK', hex(back)===hex(DEK), 'DEK='+hex(DEK));

  // 身份绑定（关键负例）：用对的身份串(ID_BOB) + 错的私钥(Alice) 解 Bob 的密文 → 必须失败。
  // 注：本负例特意只换私钥、不换身份串，专门验证「私钥本身参与绑定」，可捕获 sm3 多分块/配对类 bug。
  ok('deBob 与 deAlice 是不同私钥', hex(deBobBytes)!==hex(deAliceBytes));
  let aliceFailed=false; try{ ibeDecrypt(env, ID_BOB, deAlice); }catch(e){ aliceFailed=true; }
  ok('非接收人(Alice)私钥解 Bob 密文 → 失败', aliceFailed);

  // 防篡改：翻转密文末字节 → MAC 失败
  const tampered = env.slice(); tampered[tampered.length-1]^=0x01;
  let tamperFailed=false; try{ ibeDecrypt(tampered, ID_BOB, deBob); }catch(e){ tamperFailed=true; }
  ok('篡改密文 → 解封失败', tamperFailed);

  console.log(`\n======== 结果：${pass} 通过 / ${fail} 失败 ========`);
  process.exit(fail===0?0:1);
})().catch(e => { console.error('运行异常:', e); process.exit(1); });
