package com.securedoc.app;

import com.securedoc.app.crypto.Sm3;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/** 应用服务器 SM3（密文分块摘要用）对标国标向量 + 多分块加固。 */
class Sm3Test {

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    @Test
    void abcVector() {
        assertThat(hex(Sm3.digest("abc".getBytes(StandardCharsets.US_ASCII))))
                .isEqualTo("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
    }

    @Test
    void multiBlock200() {   // 200 字节多分块（与修复后的 guanzhi sm3 交叉核对值一致）
        byte[] m = new byte[200];
        Arrays.fill(m, (byte) 0x61);
        assertThat(hex(Sm3.digest(m)))
                .isEqualTo("a8da99c801bbd65ec00992ed5cbef851f275e98da9fb2d4f5be184f81473d5dd");
    }

    // ---- HMAC-SM3（M-3 审计链用）：向量由独立实现 OpenSSL 经 Python hmac 生成，非自产自检 ----

    @Test
    void hmacVectorShortKey() {   // RFC 4231 用例1 的数据布局：key=0x0b×20, data="Hi There"
        byte[] key = new byte[20];
        Arrays.fill(key, (byte) 0x0b);
        assertThat(hex(Sm3.hmac(key, "Hi There".getBytes(StandardCharsets.US_ASCII))))
                .isEqualTo("51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70");
    }

    @Test
    void hmacVectorTextKey() {   // RFC 4231 用例2 的数据布局：key="Jefe"
        assertThat(hex(Sm3.hmac("Jefe".getBytes(StandardCharsets.US_ASCII),
                "what do ya want for nothing?".getBytes(StandardCharsets.US_ASCII))))
                .isEqualTo("2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882");
    }

    @Test
    void hmacVectorLongKey() {   // key 超块长(131B > 64B)，须先摘要再补零：RFC 4231 用例6 的数据布局
        byte[] key = new byte[131];
        Arrays.fill(key, (byte) 0xaa);
        assertThat(hex(Sm3.hmac(key,
                "Test Using Larger Than Block-Size Key - Hash Key First".getBytes(StandardCharsets.US_ASCII))))
                .isEqualTo("b4fd844e13342002f0b2e0690ea7741f1497d993a70494cea601e657bedf67a0");
    }
}
