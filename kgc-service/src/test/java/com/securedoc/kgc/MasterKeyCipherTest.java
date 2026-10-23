package com.securedoc.kgc;

import com.securedoc.kgc.crypto.MasterKeyCipher;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/** 主密钥落盘加密（PBKDF2 + AES-GCM）密封/解封单测。 */
class MasterKeyCipherTest {

    private static final char[] PASS = "correct-horse-battery-staple".toCharArray();

    @Test
    void sealOpenRoundTrip() {
        byte[] secret = new byte[32];
        for (int i = 0; i < 32; i++) secret[i] = (byte) (i * 7 + 1);
        String blob = MasterKeyCipher.seal(secret, PASS, 1);

        MasterKeyCipher.Sealed s = MasterKeyCipher.open(blob, PASS);
        assertEquals(1, s.keyVersion());
        assertArrayEquals(secret, s.plaintext());
    }

    @Test
    void blobIsCiphertextNotPlaintext() {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 0xAB);
        String blob = MasterKeyCipher.seal(secret, PASS, 1);
        byte[] decoded = Base64.getDecoder().decode(blob);
        // 头部 magic + 不含明文密钥（GCM 密文随机化）
        assertEquals("SM9KGCv1", new String(decoded, 0, 8));
        String hexBlob = bytesToHex(decoded);
        assertFalse(hexBlob.contains(bytesToHex(secret)), "落盘内容不得包含主私钥明文");
    }

    @Test
    void wrongPassphraseFails() {
        String blob = MasterKeyCipher.seal(new byte[32], PASS, 1);
        assertThrows(IllegalStateException.class,
                () -> MasterKeyCipher.open(blob, "wrong-pass".toCharArray()));
    }

    @Test
    void tamperedBlobFails() {
        byte[] secret = new byte[32];
        String blob = MasterKeyCipher.seal(secret, PASS, 1);
        byte[] decoded = Base64.getDecoder().decode(blob);
        decoded[decoded.length - 1] ^= 0x01;   // 翻转密文最后一字节
        String tampered = Base64.getEncoder().encodeToString(decoded);
        assertThrows(IllegalStateException.class, () -> MasterKeyCipher.open(tampered, PASS));
    }

    @Test
    void emptyPassphraseRejected() {
        assertThrows(IllegalStateException.class, () -> MasterKeyCipher.seal(new byte[32], new char[0], 1));
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}
