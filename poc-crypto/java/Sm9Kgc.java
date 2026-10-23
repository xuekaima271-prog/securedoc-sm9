import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * SM9 KGC（原生 Java，无配对）—— master keygen + 按身份提取私钥。
 * G1/G2 点运算逐字移植自 guanzhi/GmSSL-JS（标准 Jacobian，曲线 y^2=x^3+5）。
 * 目的：证明 Java 产出的 Ppub_e(G1) / de(G2) 与浏览器 JS(同库) 字节级一致 → Java↔JS 互通。
 * H1 由命令行传入（避免此处再移植 SM3；正式 KGC 会用 Java SM3）。
 * 用法：java Sm9Kgc <h1_hex>   输出 ke / Ppub_e / de 的 hex。
 */
public class Sm9Kgc {
    static final BigInteger P = new BigInteger("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d", 16);
    static final BigInteger N = new BigInteger("b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25", 16);
    static final BigInteger ZERO = BigInteger.ZERO, ONE = BigInteger.ONE;

    // G1 生成元 P1
    static final BigInteger[] P1 = {
        new BigInteger("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD", 16),
        new BigInteger("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616", 16),
        ONE };
    // G2 生成元 P2 (Fp2 坐标)
    static final BigInteger[][] P2 = {
        { new BigInteger("3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b", 16),
          new BigInteger("85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141", 16) },
        { new BigInteger("a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7", 16),
          new BigInteger("17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96", 16) },
        { ONE, ZERO } };

    // ---------- Fp ----------
    static BigInteger fpAdd(BigInteger a, BigInteger b){ return a.add(b).mod(P); }
    static BigInteger fpSub(BigInteger a, BigInteger b){ return a.subtract(b).mod(P); }
    static BigInteger fpMul(BigInteger a, BigInteger b){ return a.multiply(b).mod(P); }
    static BigInteger fpSqr(BigInteger a){ return a.multiply(a).mod(P); }
    static BigInteger fpDbl(BigInteger a){ return a.add(a).mod(P); }
    static BigInteger fpTri(BigInteger a){ return fpAdd(fpDbl(a), a); }
    static BigInteger fpDiv2(BigInteger a){ return a.testBit(0) ? a.add(P).shiftRight(1) : a.shiftRight(1); }
    static BigInteger fpNeg(BigInteger a){ return a.signum()==0 ? a : P.subtract(a); }
    static BigInteger fpInv(BigInteger a){ return a.modInverse(P); }

    // ---------- Fp2 = Fp[u]/(u^2+2) ----------
    static BigInteger[] f2(BigInteger a, BigInteger b){ return new BigInteger[]{a,b}; }
    static BigInteger[] f2Add(BigInteger[] a, BigInteger[] b){ return f2(fpAdd(a[0],b[0]), fpAdd(a[1],b[1])); }
    static BigInteger[] f2Sub(BigInteger[] a, BigInteger[] b){ return f2(fpSub(a[0],b[0]), fpSub(a[1],b[1])); }
    static BigInteger[] f2Dbl(BigInteger[] a){ return f2(fpDbl(a[0]), fpDbl(a[1])); }
    static BigInteger[] f2Tri(BigInteger[] a){ return f2Add(f2Dbl(a), a); }
    static BigInteger[] f2Div2(BigInteger[] a){ return f2(fpDiv2(a[0]), fpDiv2(a[1])); }
    static BigInteger[] f2Mul(BigInteger[] a, BigInteger[] b){
        BigInteger r0 = fpSub(fpMul(a[0],b[0]), fpDbl(fpMul(a[1],b[1])));
        BigInteger r1 = fpAdd(fpMul(a[0],b[1]), fpMul(a[1],b[0]));
        return f2(r0, r1);
    }
    static BigInteger[] f2Sqr(BigInteger[] a){
        BigInteger r0 = fpSub(fpSqr(a[0]), fpDbl(fpSqr(a[1])));
        BigInteger r1 = fpDbl(fpMul(a[0], a[1]));
        return f2(r0, r1);
    }
    static BigInteger[] f2Inv(BigInteger[] a){
        if (a[0].signum()==0) return f2(ZERO, fpNeg(fpInv(fpDbl(a[1]))));
        if (a[1].signum()==0) return f2(fpInv(a[0]), ZERO);
        BigInteger k = fpInv(fpAdd(fpSqr(a[0]), fpDbl(fpSqr(a[1]))));
        return f2(fpMul(a[0],k), fpNeg(fpMul(a[1],k)));
    }
    static boolean f2IsZero(BigInteger[] a){ return a[0].signum()==0 && a[1].signum()==0; }
    static boolean f2IsOne(BigInteger[] a){ return a[0].equals(ONE) && a[1].signum()==0; }

    // ---------- G1 (Jacobian) ----------
    static boolean g1Inf(BigInteger[] p){ return p[2].signum()==0; }
    static BigInteger[] g1Double(BigInteger[] p){
        if (g1Inf(p)) return p.clone();
        BigInteger X1=p[0], Y1=p[1], Z1=p[2];
        BigInteger T2=fpTri(fpSqr(X1));
        BigInteger Y3=fpDbl(Y1);
        BigInteger Z3=fpMul(Y3,Z1);
        Y3=fpSqr(Y3);
        BigInteger T3=fpMul(Y3,X1);
        Y3=fpSqr(Y3); Y3=fpDiv2(Y3);
        BigInteger X3=fpSqr(T2);
        BigInteger T1=fpDbl(T3);
        X3=fpSub(X3,T1);
        T1=fpSub(T3,X3); T1=fpMul(T1,T2);
        Y3=fpSub(T1,Y3);
        return new BigInteger[]{X3,Y3,Z3};
    }
    static BigInteger[] g1Add(BigInteger[] p, BigInteger[] q){
        if (g1Inf(q)) return p.clone();
        if (g1Inf(p)) return q.clone();
        BigInteger X1=p[0],Y1=p[1],Z1=p[2],x2=q[0],y2=q[1];
        BigInteger T1=fpSqr(Z1);
        BigInteger T2=fpMul(T1,Z1);
        T1=fpMul(T1,x2); T2=fpMul(T2,y2);
        T1=fpSub(T1,X1); T2=fpSub(T2,Y1);
        if (T1.signum()==0){
            if (T2.signum()==0) return g1Double(q);
            return new BigInteger[]{ONE,ONE,ZERO};
        }
        BigInteger Z3=fpMul(Z1,T1);
        BigInteger T3=fpSqr(T1);
        BigInteger T4=fpMul(T3,T1);
        T3=fpMul(T3,X1);
        T1=fpDbl(T3);
        BigInteger X3=fpSqr(T2);
        X3=fpSub(X3,T1); X3=fpSub(X3,T4);
        T3=fpSub(T3,X3); T3=fpMul(T3,T2);
        T4=fpMul(T4,Y1);
        BigInteger Y3=fpSub(T3,T4);
        return new BigInteger[]{X3,Y3,Z3};
    }
    static BigInteger[] g1Mul(BigInteger k, BigInteger[] p){
        BigInteger[] Q = {ONE,ONE,ZERO};
        String bits = k.toString(2);
        for (int i=0;i<bits.length();i++){ Q=g1Double(Q); if (bits.charAt(i)=='1') Q=g1Add(Q,p); }
        return Q;
    }
    static BigInteger[] g1Affine(BigInteger[] p){
        if (p[2].signum()==0 || p[2].equals(ONE)) return p;
        BigInteger zi=fpInv(p[2]);
        BigInteger Y=fpMul(p[1],zi);
        BigInteger z2=fpSqr(zi);
        BigInteger X=fpMul(p[0],z2);
        Y=fpMul(Y,z2);
        return new BigInteger[]{X,Y,ONE};
    }

    // ---------- G2 twist (Jacobian over Fp2) ----------
    static boolean g2Inf(BigInteger[][] p){ return f2IsZero(p[2]); }
    static BigInteger[][] g2Double(BigInteger[][] p){
        if (g2Inf(p)) return p;
        BigInteger[] X1=p[0],Y1=p[1],Z1=p[2];
        BigInteger[] T2=f2Tri(f2Sqr(X1));
        BigInteger[] Y3=f2Dbl(Y1);
        BigInteger[] Z3=f2Mul(Y3,Z1);
        Y3=f2Sqr(Y3);
        BigInteger[] T3=f2Mul(Y3,X1);
        Y3=f2Sqr(Y3); Y3=f2Div2(Y3);
        BigInteger[] X3=f2Sqr(T2);
        BigInteger[] T1=f2Dbl(T3);
        X3=f2Sub(X3,T1);
        T1=f2Sub(T3,X3); T1=f2Mul(T1,T2);
        Y3=f2Sub(T1,Y3);
        return new BigInteger[][]{X3,Y3,Z3};
    }
    static BigInteger[][] g2Add(BigInteger[][] p, BigInteger[][] q){
        if (g2Inf(q)) return p;
        if (g2Inf(p)) return q;
        BigInteger[] X1=p[0],Y1=p[1],Z1=p[2],x2=q[0],y2=q[1];
        BigInteger[] T1=f2Sqr(Z1);
        BigInteger[] T2=f2Mul(T1,Z1);
        T1=f2Mul(T1,x2); T2=f2Mul(T2,y2);
        T1=f2Sub(T1,X1); T2=f2Sub(T2,Y1);
        if (f2IsZero(T1)){
            if (f2IsZero(T2)) return g2Double(q);
            return new BigInteger[][]{{ONE,ZERO},{ONE,ZERO},{ZERO,ZERO}};
        }
        BigInteger[] Z3=f2Mul(Z1,T1);
        BigInteger[] T3=f2Sqr(T1);
        BigInteger[] T4=f2Mul(T3,T1);
        T3=f2Mul(T3,X1);
        T1=f2Dbl(T3);
        BigInteger[] X3=f2Sqr(T2);
        X3=f2Sub(X3,T1); X3=f2Sub(X3,T4);
        T3=f2Sub(T3,X3); T3=f2Mul(T3,T2);
        T4=f2Mul(T4,Y1);
        BigInteger[] Y3=f2Sub(T3,T4);
        return new BigInteger[][]{X3,Y3,Z3};
    }
    static BigInteger[][] g2Mul(BigInteger k, BigInteger[][] p){
        BigInteger[][] Q = {{ONE,ZERO},{ONE,ZERO},{ZERO,ZERO}};
        String bits = k.toString(2);
        for (int i=0;i<bits.length();i++){ Q=g2Double(Q); if (bits.charAt(i)=='1') Q=g2Add(Q,p); }
        return Q;
    }
    static BigInteger[][] g2Affine(BigInteger[][] p){
        if (f2IsZero(p[2]) || f2IsOne(p[2])) return p;
        BigInteger[] zi=f2Inv(p[2]);
        BigInteger[] Y=f2Mul(p[1],zi);
        BigInteger[] z2=f2Sqr(zi);
        BigInteger[] X=f2Mul(p[0],z2);
        Y=f2Mul(Y,z2);
        return new BigInteger[][]{X,Y,{ONE,ZERO}};
    }

    static String hex(BigInteger v){ String s=v.mod(P).toString(16); return "0".repeat(Math.max(0,64-s.length()))+s; }

    public static void main(String[] args){
        BigInteger h1 = new BigInteger(args[0], 16);
        // 主密钥 ke（CSPRNG）；演示可由 args[1] 固定，便于和 JS 交叉核对
        BigInteger ke;
        if (args.length >= 2) ke = new BigInteger(args[1], 16).mod(N);
        else { SecureRandom rng=new SecureRandom(); BigInteger k; do{ k=new BigInteger(256,rng).mod(N);}while(k.signum()==0); ke=k; }

        BigInteger[] Ppub = g1Affine(g1Mul(ke, P1));               // Ppub_e=[ke]P1 (G1)
        BigInteger t1 = h1.add(ke).mod(N);
        BigInteger t2 = ke.multiply(t1.modInverse(N)).mod(N);
        BigInteger[][] de = g2Affine(g2Mul(t2, P2));               // de=[t2]P2 (G2)

        System.out.println("ke="    + hex(ke));
        System.out.println("ppubx=" + hex(Ppub[0]));
        System.out.println("ppuby=" + hex(Ppub[1]));
        System.out.println("dex0="  + hex(de[0][0]));
        System.out.println("dex1="  + hex(de[0][1]));
        System.out.println("dey0="  + hex(de[1][0]));
        System.out.println("dey1="  + hex(de[1][1]));
    }
}
