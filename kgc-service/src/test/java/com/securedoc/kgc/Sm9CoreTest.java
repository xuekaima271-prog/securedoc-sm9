package com.securedoc.kgc;

import com.securedoc.kgc.crypto.Sm9Core;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * SM9 核心字节级对标。
 *
 * 基准真值由 guanzhi/GmSSL-JS 真库算出（poc-crypto/sm9-expected-values.cjs），
 * 关键点：本测试用 Java 自算的 H1（Sm9Core.h1，内部用 Sm3），不再像 PoC 那样从 JS 传参，
 * 仍能逐字节命中 JS 真值 —— 即清零账本 SM9-9 的「H1 传参」遗留缺口。
 */
class Sm9CoreTest {

    // 固定主私钥 ke（与 poc-crypto/sm9-interop.cjs 一致），便于交叉核对
    private static final BigInteger KE =
            new BigInteger("000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4", 16);
    private static final byte[] ID_BOB =
            "user:corp001:10002:bob@example.com".getBytes(StandardCharsets.UTF_8);

    // 来自 sm9-expected-values.cjs 的权威输出
    private static final String EXP_H1    = "57ed70adc9bdc485c8163485aa96b934b8aa226b5aacecf1d5cc380bca850f06";
    private static final String EXP_PPUBX = "770f06f6a183fc3146cc105e1b3a0c53c2ce86e3dda3a5e79382158b88ca3c8b";
    private static final String EXP_PPUBY = "ac8d759b71c79a389c2f6b4b9bf3fc76ae507731810d2efadd2a77efbccc352c";
    private static final String EXP_DEX0  = "7db3c7e9fa34a5c8f9ad0fd875e368b8d6ef3daa9cec2097a7eb0bf32c5643aa";
    private static final String EXP_DEX1  = "8b0c93d050d7e57caace1da194573fd0c3469458d2c69b5eb233d5fbaa8d67fc";
    private static final String EXP_DEY0  = "04a434e447c06226e1a99c65a7993004a8ba4c1659e03f35113b866ef2470486";
    private static final String EXP_DEY1  = "7710e2187ef5160eb4e5fe5a99e8b8631cc9628921121902e372d58ca0c59bef";

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
    private static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    @Test
    void h1MatchesJs() {
        // Java 用 Sm3 自算 H1，须与 JS 真值逐字节一致
        BigInteger h1 = Sm9Core.h1(ID_BOB, Sm9Core.HID_ENC);
        assertEquals(EXP_H1, hex(Sm9Core.to32(h1)));
    }

    @Test
    void masterPublicKeyMatchesJs() {
        byte[] ppub = Sm9Core.masterPublicKey(KE);
        assertEquals(64, ppub.length);
        assertArrayEquals(unhex(EXP_PPUBX), Arrays.copyOfRange(ppub, 0, 32), "Ppub_e.x");
        assertArrayEquals(unhex(EXP_PPUBY), Arrays.copyOfRange(ppub, 32, 64), "Ppub_e.y");
    }

    @Test
    void extractMatchesJs() {
        byte[] de = Sm9Core.extract(ID_BOB, KE);
        assertEquals(128, de.length);
        assertEquals(EXP_DEX0 + EXP_DEX1 + EXP_DEY0 + EXP_DEY1, hex(de),
                "de(G2) 须与 JS 自算逐字节一致");
    }
}
