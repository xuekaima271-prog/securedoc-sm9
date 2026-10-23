package com.securedoc.app;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.securedoc.app.entity.SecurityEvent;
import com.securedoc.app.mapper.SecurityEventMapper;
import com.securedoc.app.service.AuditService;
import com.securedoc.app.service.LoginThrottleService;
import com.securedoc.app.service.SecurityEventService;
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

/** Step15 安全事件（§2.2.12）：埋点触发、查询过滤、RBAC。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class SecurityEventTest {

    @Autowired SecurityEventService securityEventService;
    @Autowired SecurityEventMapper securityEventMapper;
    @Autowired LoginThrottleService throttleService;
    @Autowired AuditService auditService;
    @Autowired com.securedoc.app.mapper.AuditLogMapper auditLogMapper;
    @Autowired MockMvc mvc;

    private List<SecurityEvent> byType(String type) {
        return securityEventMapper.selectList(
                new LambdaQueryWrapper<SecurityEvent>().eq(SecurityEvent::getEventType, type));
    }

    @Test
    void 连续登录失败达阈值_产生暴力破解锁定事件() {
        throttleService.clearAll();
        for (int i = 0; i < 5; i++) {
            throttleService.recordFailure("victim", "9.9.9.9");
        }
        // 按本用例特征过滤（其他测试类可能提交过同类型事件）
        List<SecurityEvent> evts = byType("BRUTE_FORCE_LOCK").stream()
                .filter(e -> "victim".equals(e.getResource())).toList();
        assertThat(evts).hasSize(1);   // 只在恰好越过阈值时记一次
        assertThat(evts.get(0).getSeverity()).isEqualTo("HIGH");
        assertThat(evts.get(0).getClientIp()).isEqualTo("9.9.9.9");
        throttleService.clearAll();
    }

    @Test
    void 单IP失败越过阈值_产生IP限流事件_仅一次() {
        throttleService.clearAll();
        for (int i = 0; i < 12; i++) {
            throttleService.recordFailure("user" + i, "8.8.8.8");   // 不同账号避免账号锁定干扰
        }
        List<SecurityEvent> evts = byType("IP_THROTTLED").stream()
                .filter(e -> "8.8.8.8".equals(e.getClientIp())).toList();
        assertThat(evts).hasSize(1);
        throttleService.clearAll();
    }

    @Test
    @WithUserDetails("alice")
    void 员工越权访问管理接口_403且产生越权事件() throws Exception {
        mvc.perform(get("/api/admin/users")).andExpect(status().isForbidden());
        List<SecurityEvent> evts = byType("ACCESS_DENIED").stream()
                .filter(e -> Long.valueOf(10001L).equals(e.getActorId())
                        && e.getResource() != null && e.getResource().contains("/api/admin/users"))
                .toList();
        assertThat(evts).isNotEmpty();
    }

    @Test
    void 审计链被篡改_verifyChain产生链断裂事件() {
        auditService.record(10001L, "LOGIN", "AUTH", "alice", "1.1.1.1", "ua", "登录成功");
        var rows = auditLogMapper.selectList(new LambdaQueryWrapper<com.securedoc.app.entity.AuditLog>()
                .orderByAsc(com.securedoc.app.entity.AuditLog::getId));
        var victim = rows.get(rows.size() - 1);
        victim.setDetail("被篡改");
        auditLogMapper.updateById(victim);

        assertThat(auditService.verifyChain().valid()).isFalse();
        assertThat(byType("AUDIT_CHAIN_BROKEN")).isNotEmpty();
    }

    @Test
    @WithUserDetails("auditor")
    void 审计员查询安全事件_分页与过滤生效() throws Exception {
        securityEventService.record("ACCESS_DENIED", "MEDIUM", 10001L, "1.1.1.1", "GET /x", "t1");
        securityEventService.record("BRUTE_FORCE_LOCK", "HIGH", null, "2.2.2.2", "bob", "t2");

        mvc.perform(get("/api/audit/security-events").param("severity", "HIGH"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.records[0].eventType").value("BRUTE_FORCE_LOCK"));
        mvc.perform(get("/api/audit/security-events").param("eventType", "ACCESS_DENIED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.records[0].detail").value("t1"));
    }

    @Test
    @WithUserDetails("alice")
    void 员工查询安全事件_403() throws Exception {
        mvc.perform(get("/api/audit/security-events"))
                .andExpect(status().isForbidden());
    }
}
