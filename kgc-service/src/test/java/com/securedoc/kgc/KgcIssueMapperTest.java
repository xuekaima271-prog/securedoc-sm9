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
@SpringBootTest
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
