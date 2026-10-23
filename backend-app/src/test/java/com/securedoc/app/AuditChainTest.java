package com.securedoc.app;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.securedoc.app.common.AuditChainResult;
import com.securedoc.app.entity.AuditLog;
import com.securedoc.app.mapper.AuditLogMapper;
import com.securedoc.app.service.AuditService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Step8 审计 SM3 哈希链：链式衔接、创世、篡改检出、verify 接口鉴权。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditChainTest {

    @Autowired AuditService auditService;
    @Autowired AuditLogMapper auditLogMapper;
    @Autowired MockMvc mvc;

    private List<AuditLog> allAsc() {
        return auditLogMapper.selectList(new LambdaQueryWrapper<AuditLog>().orderByAsc(AuditLog::getId));
    }

    @Test
    void 哈希链_创世与逐条衔接_校验通过() {
        auditService.record(10001L, "LOGIN", "AUTH", "alice", "1.1.1.1", "ua", "登录成功");
        auditService.record(10001L, "FILE_UPLOAD", "FILE", "f1", "1.1.1.1", "ua", "上传");
        auditService.record(10002L, "FILE_DOWNLOAD", "FILE", "f1", "2.2.2.2", "ua", "下载");

        List<AuditLog> rows = allAsc();
        assertThat(rows).hasSizeGreaterThanOrEqualTo(3);
        // 创世：首条 previousHash = GENESIS
        assertThat(rows.get(0).getPreviousHash()).isEqualTo("GENESIS");
        // 逐条衔接：第 i 条 previousHash == 第 i-1 条 currentHash
        for (int i = 1; i < rows.size(); i++) {
            assertThat(rows.get(i).getPreviousHash()).isEqualTo(rows.get(i - 1).getCurrentHash());
        }
        AuditChainResult r = auditService.verifyChain();
        assertThat(r.valid()).isTrue();
        assertThat(r.brokenAtId()).isNull();
    }

    @Test
    void 篡改历史记录_校验检出断裂() {
        auditService.record(10001L, "LOGIN", "AUTH", "alice", "1.1.1.1", "ua", "登录成功");
        auditService.record(10001L, "FILE_UPLOAD", "FILE", "f1", "1.1.1.1", "ua", "原始详情");
        auditService.record(10002L, "LOGOUT", "AUTH", "bob", "2.2.2.2", "ua", "登出");

        List<AuditLog> rows = allAsc();
        AuditLog victim = rows.get(1);
        // 直接篡改历史记录的 detail（不重算哈希）—— 模拟攻击者改库
        victim.setDetail("被篡改的详情");
        auditLogMapper.updateById(victim);

        AuditChainResult r = auditService.verifyChain();
        assertThat(r.valid()).isFalse();
        assertThat(r.brokenAtId()).isEqualTo(victim.getId());
    }

    @Test
    @WithUserDetails("auditor")
    void verify接口_审计员可访问_返回valid() throws Exception {
        mvc.perform(get("/api/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.valid").value(true));
    }

    @Test
    @WithUserDetails("alice")
    void verify接口_普通员工_403() throws Exception {
        mvc.perform(get("/api/audit/verify"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PERMISSION_DENIED"));
    }
}
