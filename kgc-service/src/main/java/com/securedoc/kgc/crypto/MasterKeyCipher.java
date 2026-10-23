package com.securedoc.kgc.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * KGC 主密钥落盘加密（SM9-5「安全存储」）。
 *
 * 方案：口令 →(PBKDF2WithHmacSHA256, 210000 次)→ 256bit KEK →(AES-256-GCM)→ 主私钥密文。
 * 每次密封用新随机 salt(16) + iv(12)，GCM 自带完整性校验（口令错/密文被篡改 → 解封抛异常）。
 * 落盘格式（定长二进制后整体 Base64）：
 *   magic "SM9KGCv1"(8) | keyVersion(4 BE) | salt(16) | iv(12) | ciphertext(plaintext+GCM tag)
 *
 * 仅做密码学密封，不碰文件 IO（便于纯单测）；文件读写与生命周期在 Sm9MasterKeyService。
 */
public final class MasterKeyCipher {

    private MasterKeyCipher() {}

    private static final byte[] MAGIC = "SM9KGCv1".getBytes(StandardCharsets.US_ASCII);
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final int PBKDF2_ITERS = 210_000;
    private static final int KEK_BITS = 256;

    private static final SecureRandom RNG = new SecureRandom();

    /** 解封结果：密钥版本号 + 明文（主私钥字节）。 */
    public record Sealed(int keyVersion, byte[] plaintext) {}

    private static void requirePassphrase(char[] passphrase) {
        if (passphrase == null || passphrase.length == 0) {
            throw new IllegalStateException("KGC 主密钥口令未配置（kgc.master-key.passphrase / 环境变量 KGC_MASTER_PASSPHRASE）");
        }
    }

    private static SecretKey deriveKek(char[] passphrase, byte[] salt) {
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERS, KEK_BITS);
            byte[] kek = f.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return new SecretKeySpec(kek, "AES");
        } catch (Exception e) {
            throw new IllegalStateException("派生 KGC 主密钥加密密钥失败", e);
        }
    }

    /** 密封：明文 + 口令 + 版本号 → Base64 文本（写入 keystore 文件）。 */
    public static String seal(byte[] plaintext, char[] passphrase, int keyVersion) {
        requirePassphrase(passphrase);
        try {
            byte[] salt = new byte[SALT_LEN];
            byte[] iv = new byte[IV_LEN];
            RNG.nextBytes(salt);
            RNG.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, deriveKek(passphrase, salt), new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = c.doFinal(plaintext);

            ByteBuffer buf = ByteBuffer.allocate(MAGIC.length + 4 + SALT_LEN + IV_LEN + ct.length);
            buf.put(MAGIC).putInt(keyVersion).put(salt).put(iv).put(ct);
            return Base64.getEncoder().encodeToString(buf.array());
        } catch (Exception e) {
            throw new IllegalStateException("密封 KGC 主密钥失败", e);
        }
    }

    /** 解封：Base64 文本 + 口令 → 版本号 + 明文。口令错或密文被篡改将抛异常。 */
    public static Sealed open(String blob, char[] passphrase) {
        requirePassphrase(passphrase);
        try {
            byte[] all = Base64.getDecoder().decode(blob.trim());
            ByteBuffer buf = ByteBuffer.wrap(all);
            byte[] magic = new byte[MAGIC.length];
            buf.get(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new IllegalStateException("KGC 主密钥文件格式不识别（magic 不匹配）");
            }
            int keyVersion = buf.getInt();
            byte[] salt = new byte[SALT_LEN];
            byte[] iv = new byte[IV_LEN];
            buf.get(salt);
            buf.get(iv);
            byte[] ct = new byte[buf.remaining()];
            buf.get(ct);

            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, deriveKek(passphrase, salt), new GCMParameterSpec(TAG_BITS, iv));
            byte[] plaintext = c.doFinal(ct);   // GCM tag 校验失败（口令错/被篡改）会抛 AEADBadTagException
            return new Sealed(keyVersion, plaintext);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("解封 KGC 主密钥失败（口令错误或文件损坏/被篡改）", e);
        }
    }
}
