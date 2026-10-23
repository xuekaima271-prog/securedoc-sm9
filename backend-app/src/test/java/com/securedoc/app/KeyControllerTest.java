package com.securedoc.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.securedoc.app.client.KgcClient;
import com.securedoc.app.entity.UserKey;
import com.securedoc.app.mapper.UserKeyMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import com.securedoc.app.service.LoginThrottleService;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * 密钥接口（Step 6）：me/status、recipients、master-public-key、init（代理 KGC，mock 掉外部依赖）、CORS 预检。
 * 安全要点：/init 无 userId 入参——结构上只能签发会话用户自己的身份。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class KeyControllerTest {

    @Autowired MockMvc mvc;
    @Autowired UserKeyMapper userKeyMapper;
    @MockitoBean KgcClient kgcClient;
    @Autowired LoginThrottleService throttle;
    private final ObjectMapper om = new ObjectMapper();

    @BeforeEach
    @AfterEach
    void resetThrottle() {
        throttle.clearAll();
    }

    @Test
    @WithUserDetails("bob")
    void 查我的密钥状态_未初始化() throws Exception {
        mvc.perform(get("/api/keys/me/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.identity").value("user:corp001:10002:bob@example.com"))
                .andExpect(jsonPath("$.data.keyStatus").value("UNINITIALIZED"))
                .andExpect(jsonPath("$.data.initialized").value(false));
    }

    @Test
    @WithUserDetails("alice")
    void 可选接收人列表_排除自己() throws Exception {
        mvc.perform(get("/api/keys/recipients"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[?(@.username=='alice')]").isEmpty())
                .andExpect(jsonPath("$.data[?(@.username=='bob')].identity")
                        .value("user:corp001:10002:bob@example.com"));
    }

    @Test
    @WithUserDetails("alice")
    void 取主公钥_经KGC代理() throws Exception {
        Mockito.when(kgcClient.getMasterPublicKey()).thenReturn("TUFTVEVSLVBVQktFWQ==");
        mvc.perform(get("/api/keys/master-public-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.masterPublicKey").value("TUFTVEVSLVBVQktFWQ=="));
    }

    @Test
    @WithUserDetails("bob")
    void 初始化私钥_代理KGC_更新状态为ISSUED() throws Exception {
        ObjectNode data = om.createObjectNode()
                .put("privateKeyPackage", "UFJJVktFWS1QQUNLQUdF")
                .put("issueId", "ISSUE-UUID-1")
                .put("issuedAt", "2026-06-27T10:00:00");
        Mockito.when(kgcClient.issuePrivateKey(eq(10002L), eq("user:corp001:10002:bob@example.com"), any()))
                .thenReturn(data);

        mvc.perform(post("/api/keys/init").contentType("application/json").content("{\"deviceFingerprint\":\"dev-fp\",\"password\":\"Demo@123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.privateKeyPackage").value("UFJJVktFWS1QQUNLQUdF"))
                .andExpect(jsonPath("$.data.issueId").value("ISSUE-UUID-1"))
                .andExpect(jsonPath("$.data.identity").value("user:corp001:10002:bob@example.com"));

        UserKey uk = userKeyMapper.selectByUserId(10002L);
        assertThat(uk.getKeyStatus()).isEqualTo("ISSUED");
        assertThat(uk.getDeviceBound()).isTrue();
        assertThat(uk.getLastIssueTime()).isNotNull();
    }

    @Test
    @WithUserDetails("bob")
    void 已初始化再次init_走KGC重签发_状态REISSUED() throws Exception {
        // 预置：bob 已 ISSUED（模拟换设备场景）
        UserKey uk = userKeyMapper.selectByUserId(10002L);
        uk.setKeyStatus("ISSUED");
        userKeyMapper.updateById(uk);

        ObjectNode data = om.createObjectNode()
                .put("privateKeyPackage", "UkVJU1NVRS1QQUNLQUdF")
                .put("issueId", "REISSUE-UUID-1")
                .put("issuedAt", "2026-07-09T10:00:00");
        Mockito.when(kgcClient.reissuePrivateKey(eq(10002L),
                        eq("user:corp001:10002:bob@example.com"), any(), any()))
                .thenReturn(data);

        mvc.perform(post("/api/keys/init").contentType("application/json")
                        .content("{\"deviceFingerprint\":\"new-device\",\"password\":\"Demo@123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.issueId").value("REISSUE-UUID-1"));

        // 走的是 reissue 而非 issue（两侧审计一致的关键）
        Mockito.verify(kgcClient).reissuePrivateKey(eq(10002L),
                eq("user:corp001:10002:bob@example.com"), any(), any());
        Mockito.verify(kgcClient, Mockito.never())
                .issuePrivateKey(anyLong(), anyString(), any());
        assertThat(userKeyMapper.selectByUserId(10002L).getKeyStatus()).isEqualTo("REISSUED");
    }

    @Test
    void 未登录取状态_401() throws Exception {
        mvc.perform(get("/api/keys/me/status"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithUserDetails("bob")
    void sessionWithoutPasswordCannotIssueKey() throws Exception {
        mvc.perform(post("/api/keys/init").contentType("application/json").content("{}"))
                .andExpect(status().isBadRequest());
        Mockito.verifyNoInteractions(kgcClient);
    }

    @Test
    @WithUserDetails("bob")
    void incorrectPasswordCannotReissueKey() throws Exception {
        UserKey uk = userKeyMapper.selectByUserId(10002L);
        uk.setKeyStatus("ISSUED");
        userKeyMapper.updateById(uk);
        mvc.perform(post("/api/keys/init").contentType("application/json")
                        .content("{\"password\":\"incorrect\"}"))
                .andExpect(status().isUnauthorized());
        Mockito.verifyNoInteractions(kgcClient);
        assertThat(userKeyMapper.selectByUserId(10002L).getKeyStatus()).isEqualTo("ISSUED");
    }

    @Test
    @WithUserDetails("bob")
    void repeatedPasswordFailuresAreRateLimited() throws Exception {
        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/api/keys/init").contentType("application/json")
                            .content("{\"password\":\"incorrect\"}"))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/api/keys/init").contentType("application/json")
                        .content("{\"password\":\"Demo@123\"}"))
                .andExpect(status().isTooManyRequests());
        Mockito.verifyNoInteractions(kgcClient);
    }

    @Test
    void CORS预检放行前端Origin() throws Exception {
        mvc.perform(options("/api/keys/me/status")
                        .header("Origin", "http://localhost:5173")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"))
                .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
    }
}
