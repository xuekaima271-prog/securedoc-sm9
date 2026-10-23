package com.securedoc.kgc;

import com.securedoc.kgc.crypto.Sm3;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * SM3 对标 GM/T 0004 国标向量。
 * 这两个向量（"abc" 与 "abcd"×16）正是 guanzhi/GmSSL-JS sm3.js 的 sm3_test() 所用，
 * 故通过即等价于与浏览器侧 JS sm3() 逐字节一致。
 */
class Sm3Test {

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    @Test
    void abcVector() {
        // GB/T 32905 标准向量
        assertEquals(
                "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
                hex(Sm3.digest("abc".getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    void abcd16Vector() {
        // "abcd" 重复 16 次 = 64 字节，跨块场景（标准向量）
        byte[] msg = new byte[64];
        byte[] unit = "abcd".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < 16; i++) System.arraycopy(unit, 0, msg, i * 4, 4);
        assertEquals(
                "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
                hex(Sm3.digest(msg)));
    }

    @Test
    void emptyVector() {
        // 空串向量（多实现一致）：1ab21d83...
        assertEquals(
                "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
                hex(Sm3.digest(new byte[0])));
    }

    // ---- 多分块加固：guanzhi/GmSSL-JS 的 sm3 曾有「多分块只算首块、中间块被忽略」的 bug；
    //      这里用已修复的 guanzhi 交叉核对，确保 Java 侧 SM3 多分块完全正确（KGC 的 H1 虽是单块，但仍加固）。
    private static byte[] repeat(int b, int n) { byte[] a = new byte[n]; java.util.Arrays.fill(a, (byte) b); return a; }

    @Test
    void multiBlock128() {   // 128 字节 = 2 整块
        assertEquals(
                "5fd947effbe82a5925faaee9123d43cea200cc257b28ed797505694b4bb020f6",
                hex(Sm3.digest(repeat(0x61, 128))));
    }

    @Test
    void multiBlock200() {   // 200 字节 = 3 整块 + 余
        assertEquals(
                "a8da99c801bbd65ec00992ed5cbef851f275e98da9fb2d4f5be184f81473d5dd",
                hex(Sm3.digest(repeat(0x61, 200))));
    }
}
