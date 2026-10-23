package com.securedoc.kgc;

import com.securedoc.kgc.entity.KgcPrivateKeyIssue;
import com.securedoc.kgc.mapper.KgcPrivateKeyIssueMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 签发记录 Mapper 集成测试（H2）。验证 UUID 主键插入、issuedAt 自动填充、读回字段。
 * @Transactional 测试后回滚，不污染其他用例。
 */
@SpringBootTest(properties = {
        // 测试专用 keystore: 与 kgc-service/data/ 下的真实主密钥解耦——真实钥已轮换为随机口令
        // (旧钥按已泄露处置), 测试不得依赖它, 更不得用仓库默认口令在 data/ 里再生一把。
        "kgc.master-key.passphrase=test-only-kgc-master-passphrase",
        "kgc.master-key.file=target/test-keystore/sm9-master.key"
})
@Transactional
class KgcIssueMapperTest {

    @Autowired
    KgcPrivateKeyIssueMapper mapper;

    @Test
    void 插入并读回签发记录_UUID主键与issuedAt自动填充() {
        KgcPrivateKeyIssue r = new KgcPrivateKeyIssue();
        r.setId(UUID.randomUUID().toString());
        r.setUserId(10002L);
        r.setSm9Identity("user:corp001:10002:bob@example.com");
        r.setIssueType("FIRST");
        r.setDeviceFingerprint("fp-test-xyz");
        r.setOperatorId(10002L);
        r.setClientIp("127.0.0.1");
        r.setAuditStatus("RECORDED");

        int rows = mapper.insert(r);

        assertThat(rows).isEqualTo(1);
        assertThat(r.getIssuedAt()).isNotNull();   // MetaObjectHandler 自动填充

        KgcPrivateKeyIssue got = mapper.selectById(r.getId());
        assertThat(got).isNotNull();
        assertThat(got.getUserId()).isEqualTo(10002L);
        assertThat(got.getSm9Identity()).isEqualTo("user:corp001:10002:bob@example.com");
        assertThat(got.getIssueType()).isEqualTo("FIRST");
        assertThat(got.getAuditStatus()).isEqualTo("RECORDED");
        assertThat(got.getDeviceFingerprint()).isEqualTo("fp-test-xyz");
    }
}
