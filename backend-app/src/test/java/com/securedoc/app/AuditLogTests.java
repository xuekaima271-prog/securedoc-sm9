package com.securedoc.app;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.securedoc.app.entity.AuditLog;
import com.securedoc.app.mapper.AuditLogMapper;
import com.securedoc.app.service.LoginThrottleService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Step 3.6 审计日志测试：登录/失败入库、审计员查询权限、DB-3(TEXT 中文 detail) 往返。 */
@SpringBootTest
@AutoConfigureMockMvc
class AuditLogTests {

    @Autowired MockMvc mvc;
    @Autowired AuditLogMapper auditLogMapper;
    @Autowired LoginThrottleService throttle;

    @BeforeEach
    @AfterEach
    void clean() {
        auditLogMapper.delete(null);
        throttle.clearAll();
    }

    private MockHttpSession login(String user, String pwd) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user + "\",\"password\":\"" + pwd + "\"}"))
                .andExpect(status().isOk()).andReturn();
        return (MockHttpSession) r.getRequest().getSession(false);
    }

    @Test
    void 登录成功写入LOGIN审计() throws Exception {
        login("alice", "Demo@123");
        Long n = auditLogMapper.selectCount(new QueryWrapper<AuditLog>().eq("action", "LOGIN"));
        assertThat(n).isGreaterThanOrEqualTo(1L);
    }

    @Test
    void 登录失败写入LOGIN_FAIL审计() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized());
        Long n = auditLogMapper.selectCount(new QueryWrapper<AuditLog>().eq("action", "LOGIN_FAIL"));
        assertThat(n).isGreaterThanOrEqualTo(1L);
    }

    @Test
    void 审计员可查日志_普通员工被拒() throws Exception {
        login("alice", "Demo@123");                       // 制造一条 LOGIN
        MockHttpSession auditorSession = login("auditor", "Demo@123");
        mvc.perform(get("/api/audit/logs").session(auditorSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.records").isArray())
                .andExpect(jsonPath("$.data.total").isNumber());

        MockHttpSession aliceSession = login("alice", "Demo@123");
        mvc.perform(get("/api/audit/logs").session(aliceSession))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PERMISSION_DENIED"));
    }

    @Test
    void 未登录查审计_401() throws Exception {
        mvc.perform(get("/api/audit/logs"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTH_REQUIRED"));
    }

    @Test
    void DB3_TEXT中文detail写读一致() {
        String detail = "审计详情：用户【爱丽丝】于内网登录，IP 10.0.0.1，操作合规。";
        AuditLog a = new AuditLog();
        a.setAction("TEST_DB3");
        a.setResourceType("AUTH");
        a.setDetail(detail);
        auditLogMapper.insert(a);

        AuditLog back = auditLogMapper.selectById(a.getId());
        assertThat(back).isNotNull();
        assertThat(back.getDetail()).isEqualTo(detail);   // TEXT/CLOB 往返、中文完好
        assertThat(back.getCreatedAt()).isNotNull();      // created_at 自动填充
    }
}
