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
}
