package com.securedoc.kgc.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/** 主密钥生命周期：生成→落盘→重载（Ppub_e 稳定）+ 口令错/缺失安全报错。 */
class Sm9MasterKeyServiceTest {

    @Test
    void generatesPersistsAndReloadsSameKey(@TempDir Path tmp) throws Exception {
        Path f = tmp.resolve("sm9-master.key");

        Sm9MasterKeyService s1 = new Sm9MasterKeyService("pass-correct-123", f.toString());
        s1.init();                                   // 首启：生成 + 落盘
        byte[] pub1 = s1.masterPublicKey();
        assertEquals(64, pub1.length);
        assertTrue(Files.exists(f), "应已生成 keystore 文件");

        Sm9MasterKeyService s2 = new Sm9MasterKeyService("pass-correct-123", f.toString());
        s2.init();                                   // 二启：从文件解封同一 ke
        assertArrayEquals(pub1, s2.masterPublicKey(), "二次启动 Ppub_e 必须不变（同一主密钥）");
        assertEquals(1, s2.keyVersion());

        // 同一身份在两次「启动」中提取的私钥应一致
        byte[] id = "user:corp001:10002:bob@example.com".getBytes();
        assertArrayEquals(s1.extractPrivateKey(id), s2.extractPrivateKey(id));
    }

    @Test
    void wrongPassphraseOnReloadFails(@TempDir Path tmp) throws Exception {
        Path f = tmp.resolve("sm9-master.key");
        new Sm9MasterKeyService("pass-A", f.toString()).init();
        Sm9MasterKeyService bad = new Sm9MasterKeyService("pass-B", f.toString());
        assertThrows(IllegalStateException.class, bad::init, "口令错误重载应失败");
    }

    @Test
    void emptyPassphraseRejected(@TempDir Path tmp) {
        Sm9MasterKeyService s = new Sm9MasterKeyService("", tmp.resolve("m.key").toString());
        assertThrows(IllegalStateException.class, s::init, "缺主密钥口令应安全报错，而非裸奔");
    }
}
