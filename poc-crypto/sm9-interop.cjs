/* =============================================================================
 * SM9 Java↔JS 互通实证（S4）
 * 1) JS 算 h1=H1(Bob)；用同一 ke 跑 Java KGC（原生 Java 点乘）得 Ppub_e/de
 * 2) 交叉核对：Java 的 Ppub_e/de 是否与 JS(guanzhi库) 自算的逐字节一致
 * 3) 功能互通：用 Java 产出的密钥跑 IBE 封装/解封 DEK 是否成功
 * ===========================================================================*/
const fs = require('fs');
const path = require('path');
const { randomBytes } = require('crypto');
const { execSync } = require('child_process');

const dir = path.join(__dirname, 'gmssljs');
const libCode = fs.readFileSync(path.join(dir, 'sm3.js'), 'utf8') + '\n'
              + fs.readFileSync(path.join(dir, 'sm9.js'), 'utf8') + '\n'
              + ';globalThis.__sm9 = { SM9_N, SM9_P2 };';
eval(libCode); // 函数泄漏到本作用域裸用；const 常量经 globalThis 取
const { SM9_N, SM9_P2 } = globalThis.__sm9;
const N = SM9_N, HID_ENC = 0x03;

// ---- 工具 ----
const u32be = (x) => [(x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255];
const bytesToBig = (a) => a.reduce((acc, b) => (acc << 8n) + BigInt(b), 0n);
function bigTo32(x){ const o=new Array(32); for(let i=31;i>=0;i--){o[i]=Number(x&255n);x>>=8n;} return o; }
const xorBytes = (a,b)=>a.map((x,i)=>x^b[i]);
function modInv(a,m){ let[or,r]=[((a%m)+m)%m,m],[os,s]=[1n,0n]; while(r!==0n){const q=or/r;[or,r]=[r,or-q*r];[os,s]=[s,os-q*s];} return ((os%m)+m)%m; }
function kdf(Z,kl){ let o=[],ct=1; while(o.length<kl){o=o.concat(sm3([...Z,...u32be(ct)]));ct++;} return o.slice(0,kl); }
const mac=(K2,C2)=>sm3([...C2,...K2]);
function funcH(prefix,Z,n){ const nb=n.toString(2).length, hl=Math.ceil((5*nb)/32); let Ha=[],ct=1;
  while(Ha.length<hl){Ha=Ha.concat(sm3([prefix,...Z,...u32be(ct)]));ct++;} return (bytesToBig(Ha.slice(0,hl))%(n-1n))+1n; }
const H1=(id,hid)=>funcH(0x01,[...id,hid],N);
const idToBytes=(s)=>[...Buffer.from(s,'utf8')];
function g1Affine(P){ const a=point_new(); point_get_affine(a,P); return a; }
function g1ToBytes(P){ const a=g1Affine(P); return [...bigTo32(a.X),...bigTo32(a.Y)]; }
function g2Affine(P){ const a=twist_point_new(); twist_point_get_affine(a,P); return a; }
function fp12ToBytes(f){ const o=[]; for(const fp4 of f) for(const fp2 of fp4) for(const c of fp2) o.push(...bigTo32(c)); return o; }

// ---- IBE 加解密（与 sm9-ibe-test 一致）----
function ibeEncrypt(M, idBytes, Ppub){
  const h1=H1(idBytes,HID_ENC);
  const t=point_new(); point_mul_G(t,h1);
  const QB=point_new(); point_add(QB,t,Ppub);
  const QBa=g1Affine(QB);   // 关键修复：point_mul 要求仿射基点
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

// ---- JS 参照实现（与 Java 同算法）----
function jsMasterPub(ke){ const P=point_new(); point_mul_G(P,ke); return g1Affine(P); }
function jsExtract(idBytes, ke){ const t1=(H1(idBytes,HID_ENC)+ke)%N; const t2=(ke*modInv(t1,N))%N;
  const de=twist_point_new(); twist_point_mul_G(de,t2); return g2Affine(de); }

// =============================== 主流程 ===============================
const hex=(a)=>a.map(b=>b.toString(16).padStart(2,'0')).join('');
let pass=0,fail=0; const ok=(n,c,e='')=>{c?(pass++,console.log('  ✅',n)):(fail++,console.log('  ❌',n));if(e)console.log('     ',e);};

console.log('\n======== SM9 Java↔JS 互通实证 ========');
const ID_BOB = idToBytes('user:corp001:10002:bob@example.com');
const h1 = H1(ID_BOB, HID_ENC);
const ke = 0x000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4n % N; // 固定 ke 便于交叉核对

// 跑 Java KGC（原生 Java 点乘）
const out = execSync(`java -cp java Sm9Kgc ${h1.toString(16)} ${ke.toString(16)}`, { cwd: __dirname }).toString();
const J = {}; out.trim().split(/\r?\n/).forEach(l => { const [k,v]=l.split('='); J[k]=BigInt('0x'+v); });
console.log('  · Java KGC 已产出 ke/Ppub_e/de');

// 构造 Java 的点对象
const PpubJava = { X: J.ppubx, Y: J.ppuby, Z: 1n };
const deJava   = { X: [J.dex0, J.dex1], Y: [J.dey0, J.dey1], Z: [1n, 0n] };

// 交叉核对：JS 自算 vs Java
const PpubJs = jsMasterPub(ke);
const deJs   = jsExtract(ID_BOB, ke);
ok('Java 的 Ppub_e 与 JS 自算逐字节一致',
   PpubJava.X===PpubJs.X && PpubJava.Y===PpubJs.Y,
   `Java.x=${PpubJava.X.toString(16).slice(0,16)}.. JS.x=${PpubJs.X.toString(16).slice(0,16)}..`);
ok('Java 的 de(G2) 与 JS 自算逐字节一致',
   deJava.X[0]===deJs.X[0] && deJava.X[1]===deJs.X[1] && deJava.Y[0]===deJs.Y[0] && deJava.Y[1]===deJs.Y[1]);

// 功能互通：用 Java 的密钥跑 IBE 封装/解封
const DEK = [...randomBytes(16)];
const env = ibeEncrypt(DEK, ID_BOB, PpubJava);       // 发送方用 Java 的主公钥封装
const back = ibeDecrypt(env, ID_BOB, deJava);        // 接收方用 Java 签发的私钥解封
ok('用 Java 主公钥封装 + Java 私钥解封，还原 DEK', hex(back)===hex(DEK), 'DEK='+hex(DEK));

// 交叉方向：JS 主公钥封装 → Java 私钥解封
const env2 = ibeEncrypt(DEK, ID_BOB, PpubJs);
const back2 = ibeDecrypt(env2, ID_BOB, deJava);
ok('JS 主公钥封装 + Java 私钥解封（交叉）', hex(back2)===hex(DEK));

console.log(`\n======== 结果：${pass} 通过 / ${fail} 失败 ========`);
process.exit(fail===0?0:1);
