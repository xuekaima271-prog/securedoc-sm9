package com.securedoc.kgc.service;

import com.securedoc.kgc.crypto.MasterKeyCipher;
import com.securedoc.kgc.crypto.Sm9Core;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * SM9 主密钥生命周期管理（SM9-5）。
 *
 * 启动时 load-or-generate：
 *  - 已有 keystore 文件 → 用口令解封，恢复主私钥 ke；
 *  - 没有 → SecureRandom 生成 ke，加密落盘（{@link MasterKeyCipher}），keyVersion=1。
 *
 * 主私钥 ke 始终私有、不出本服务；对外只暴露主公钥 Ppub_e 和「按身份提取私钥」能力，
 * 体现 §2.6：KGC 是独立可信安全域，应用服务器/普通管理员不持有主密钥。
 */
@Service
public class Sm9MasterKeyService {

    private static final Logger log = LoggerFactory.getLogger(Sm9MasterKeyService.class);

    private final String passphrase;
    private final Path keyFile;

    private BigInteger ke;            // 主私钥，私有，绝不对外暴露
    private byte[] masterPublicKey;   // Ppub_e，64 字节（x||y）
    private int keyVersion;

    public Sm9MasterKeyService(
            @Value("${kgc.master-key.passphrase:}") String passphrase,
            @Value("${kgc.master-key.file:data/sm9-master.key}") String file) {
        this.passphrase = passphrase;
        this.keyFile = Path.of(file);
    }

    @PostConstruct
    void init() throws IOException {
        if (Files.exists(keyFile)) {
            String blob = Files.readString(keyFile, StandardCharsets.UTF_8);
            MasterKeyCipher.Sealed sealed = MasterKeyCipher.open(blob, passphrase.toCharArray());
            this.ke = new BigInteger(1, sealed.plaintext());
            this.keyVersion = sealed.keyVersion();
            log.info("KGC 主密钥已从 {} 加载（keyVersion={}）", keyFile.toAbsolutePath(), keyVersion);
        } else {
            byte[] raw = new byte[32];
            new SecureRandom().nextBytes(raw);
            this.ke = Sm9Core.normalizeKe(new BigInteger(1, raw));
            this.keyVersion = 1;
            String blob = MasterKeyCipher.seal(Sm9Core.to32(ke), passphrase.toCharArray(), keyVersion);
            if (keyFile.toAbsolutePath().getParent() != null) {
                Files.createDirectories(keyFile.toAbsolutePath().getParent());
            }
            Files.writeString(keyFile, blob, StandardCharsets.UTF_8);
            log.warn("KGC 主密钥不存在，已新生成并加密落盘 {}（keyVersion={}）。" +
                    "生产环境务必妥善备份口令与该文件，丢失将无法再为用户签发可用私钥。", keyFile.toAbsolutePath(), keyVersion);
        }
        this.masterPublicKey = Sm9Core.masterPublicKey(ke);
        log.info("KGC 主公钥 Ppub_e 就绪（{} 字节）", masterPublicKey.length);
    }

    /** 按用户身份提取 SM9 加密私钥 de（128 字节）。主私钥 ke 不离开本服务。 */
    public byte[] extractPrivateKey(byte[] identityBytes) {
        return Sm9Core.extract(identityBytes, ke);
    }

    /** 主公钥 Ppub_e 原始字节（64 = x||y），供发送方 IBE 封装用。 */
    public byte[] masterPublicKey() {
        return masterPublicKey.clone();
    }

    /** 主公钥 Base64。 */
    public String masterPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(masterPublicKey);
    }

    public int keyVersion() {
        return keyVersion;
    }
}
