package com.securedoc.app.crypto;

/**
 * SM3 密码杂凑算法（GB/T 32905-2016 / GM/T 0004-2012），纯 Java 实现，无外部依赖。
 *
 * 应用服务器用它对**密文分块**计算/校验 SM3 摘要（账本 SM9-4 防篡改）：上传时核对客户端
 * 声明的摘要、下载时重算比对存储内容。实现含正确的多分块循环（曾在浏览器侧 guanzhi 库发现
 * 多分块 bug，故此处加固并由 Sm3Test 多分块用例锁定）。
 */
public final class Sm3 {

    private Sm3() {}

    public static final int DIGEST_LENGTH = 32;
    private static final int BLOCK_SIZE = 64;

    private static final int[] IV = {
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    private static int rotl(int x, int n) { return (x << n) | (x >>> (32 - n)); }
    private static int p0(int x) { return x ^ rotl(x, 9) ^ rotl(x, 17); }
    private static int p1(int x) { return x ^ rotl(x, 15) ^ rotl(x, 23); }

    private static int getU32(byte[] b, int off) {
        return ((b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16)
                | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
    }

    /** 计算 SM3 摘要，返回 32 字节。 */
    public static byte[] digest(byte[] msg) {
        int len = msg.length;
        int tail = 56 - (len + 1) % 64;
        if (tail < 0) tail += 64;
        int total = len + 1 + tail + 8;
        byte[] m = new byte[total];
        System.arraycopy(msg, 0, m, 0, len);
        m[len] = (byte) 0x80;
        long bitLen = (long) len * 8;
        for (int i = 0; i < 8; i++) m[total - 1 - i] = (byte) (bitLen >>> (8 * i));

        int[] v = IV.clone();
        int[] w = new int[68];
        int[] w1 = new int[64];
        for (int off = 0; off < total; off += BLOCK_SIZE) {
            for (int j = 0; j < 16; j++) w[j] = getU32(m, off + j * 4);
            for (int j = 16; j < 68; j++)
                w[j] = p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) ^ rotl(w[j - 13], 7) ^ w[j - 6];
            for (int j = 0; j < 64; j++) w1[j] = w[j] ^ w[j + 4];

            int a = v[0], b = v[1], c = v[2], d = v[3];
            int e = v[4], f = v[5], g = v[6], h = v[7];
            for (int j = 0; j < 64; j++) {
                int tj = (j < 16) ? 0x79cc4519 : 0x7a879d8a;
                int ss1 = rotl(rotl(a, 12) + e + rotl(tj, j % 32), 7);
                int ss2 = ss1 ^ rotl(a, 12);
                int ff = (j < 16) ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c));
                int gg = (j < 16) ? (e ^ f ^ g) : ((e & f) | (~e & g));
                int tt1 = ff + d + ss2 + w1[j];
                int tt2 = gg + h + ss1 + w[j];
                d = c; c = rotl(b, 9); b = a; a = tt1;
                h = g; g = rotl(f, 19); f = e; e = p0(tt2);
            }
            v[0] ^= a; v[1] ^= b; v[2] ^= c; v[3] ^= d;
            v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
        }

        byte[] out = new byte[DIGEST_LENGTH];
        for (int i = 0; i < 8; i++) {
            out[i * 4]     = (byte) (v[i] >>> 24);
            out[i * 4 + 1] = (byte) (v[i] >>> 16);
            out[i * 4 + 2] = (byte) (v[i] >>> 8);
            out[i * 4 + 3] = (byte) (v[i]);
        }
        return out;
    }

    /** SM3 摘要的 Base64 表示（与前端/数据库 sm3_digest 字段对齐）。 */
    public static String digestBase64(byte[] msg) {
        return java.util.Base64.getEncoder().encodeToString(digest(msg));
    }

    /**
     * HMAC-SM3（RFC 2104 构造，分组长度 64 与 SM3 内部块长一致）：
     * key 超块长先取摘要、再补零到块长，分别与 ipad/opad 异或后两段摘要。
     * 供审计哈希链（M-3）使用：无密钥者无法伪造/整链重算。正确性由 Sm3Test 的
     * 独立实现（OpenSSL）向量锁定（含超长 key 用例）。
     */
    public static byte[] hmac(byte[] key, byte[] msg) {
        byte[] k = key.length > BLOCK_SIZE ? digest(key) : key;
        byte[] inner = new byte[BLOCK_SIZE + msg.length];
        byte[] outerPad = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            byte kb = i < k.length ? k[i] : 0;
            inner[i] = (byte) (kb ^ 0x36);
            outerPad[i] = (byte) (kb ^ 0x5c);
        }
        System.arraycopy(msg, 0, inner, BLOCK_SIZE, msg.length);
        byte[] innerHash = digest(inner);
        byte[] outer = new byte[BLOCK_SIZE + innerHash.length];
        System.arraycopy(outerPad, 0, outer, 0, BLOCK_SIZE);
        System.arraycopy(innerHash, 0, outer, BLOCK_SIZE, innerHash.length);
        return digest(outer);
    }

    /** HMAC-SM3 的 Base64 表示。 */
    public static String hmacBase64(byte[] key, byte[] msg) {
        return java.util.Base64.getEncoder().encodeToString(hmac(key, msg));
    }
}
