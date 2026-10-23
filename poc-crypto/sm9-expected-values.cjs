/* 用 guanzhi 真 SM9 库算出「固定 ke + Bob」的权威真值（h1 / Ppub_e / de），
 * 作为 kgc-service Sm9CoreTest 的字节级对标基准。与 sm9-interop.cjs 同算法。 */
const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, 'gmssljs');
const libCode = fs.readFileSync(path.join(dir, 'sm3.js'), 'utf8') + '\n'
              + fs.readFileSync(path.join(dir, 'sm9.js'), 'utf8') + '\n'
              + ';globalThis.__sm9 = { SM9_N, SM9_P2 };';
eval(libCode);
const { SM9_N, SM9_P2 } = globalThis.__sm9;
const N = SM9_N, HID_ENC = 0x03;

const u32be = (x) => [(x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255];
const bytesToBig = (a) => a.reduce((acc, b) => (acc << 8n) + BigInt(b), 0n);
function bigTo32(x){ const o=new Array(32); for(let i=31;i>=0;i--){o[i]=Number(x&255n);x>>=8n;} return o; }
function modInv(a,m){ let[or,r]=[((a%m)+m)%m,m],[os,s]=[1n,0n]; while(r!==0n){const q=or/r;[or,r]=[r,or-q*r];[os,s]=[s,os-q*s];} return ((os%m)+m)%m; }
function funcH(prefix,Z,n){ const nb=n.toString(2).length, hl=Math.ceil((5*nb)/32); let Ha=[],ct=1;
  while(Ha.length<hl){Ha=Ha.concat(sm3([prefix,...Z,...u32be(ct)]));ct++;} return (bytesToBig(Ha.slice(0,hl))%(n-1n))+1n; }
const H1=(id,hid)=>funcH(0x01,[...id,hid],N);
const idToBytes=(s)=>[...Buffer.from(s,'utf8')];
function g1Affine(P){ const a=point_new(); point_get_affine(a,P); return a; }
function g2Affine(P){ const a=twist_point_new(); twist_point_get_affine(a,P); return a; }
const hex32=(x)=>bigTo32(x).map(b=>b.toString(16).padStart(2,'0')).join('');

const ID_BOB = idToBytes('user:corp001:10002:bob@example.com');
const ke = 0x000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4n % N;
const h1 = H1(ID_BOB, HID_ENC);

const PpubP=point_new(); point_mul_G(PpubP,ke); const Ppub=g1Affine(PpubP);
const t1=(h1+ke)%N, t2=(ke*modInv(t1,N))%N;
const deP=twist_point_new(); twist_point_mul_G(deP,t2); const de=g2Affine(deP);

console.log(JSON.stringify({
  identity: 'user:corp001:10002:bob@example.com',
  ke:    hex32(ke),
  h1:    hex32(h1),
  ppubx: hex32(Ppub.X), ppuby: hex32(Ppub.Y),
  dex0:  hex32(de.X[0]), dex1: hex32(de.X[1]),
  dey0:  hex32(de.Y[0]), dey1: hex32(de.Y[1]),
}, null, 2));
