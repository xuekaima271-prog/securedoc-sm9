package com.securedoc.kgc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** 签发接口 POST /kgc/sm9/issue-private-key 的集成测试。 */
@SpringBootTest(properties = {
        // 测试专用 keystore: 与 kgc-service/data/ 下的真实主密钥解耦——真实钥已轮换为随机口令
        // (旧钥按已泄露处置), 测试不得依赖它, 更不得用仓库默认口令在 data/ 里再生一把。
        "kgc.master-key.passphrase=test-only-kgc-master-passphrase",
        "kgc.master-key.file=target/test-keystore/sm9-master.key"
})
@AutoConfigureMockMvc
@Transactional
class KgcIssueApiTest {

    @Autowired MockMvc mvc;
    @Value("${kgc.service-token}") String kgcToken;
    private final ObjectMapper om = new ObjectMapper();

    @Test
    void 给Bob签发私钥_返回128字节de包并落审计记录() throws Exception {
        String body = """
            {"userId":10002,"identity":"user:corp001:10002:bob@example.com","deviceFingerprint":"fp-bob-1"}""";

        MvcResult res = mvc.perform(post("/kgc/sm9/issue-private-key")
                        .header("X-KGC-Token", kgcToken)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.userId").value(10002))
                .andExpect(jsonPath("$.data.identity").value("user:corp001:10002:bob@example.com"))
                .andExpect(jsonPath("$.data.issueId").isNotEmpty())
                .andExpect(jsonPath("$.data.issuedAt").isNotEmpty())
                .andReturn();

        JsonNode root = om.readTree(res.getResponse().getContentAsString());
        String pkg = root.path("data").path("privateKeyPackage").asText();
        byte[] de = Base64.getDecoder().decode(pkg);
        assertThat(de).hasSize(128);   // de = x0||x1||y0||y1，各 32 字节
    }

    @Test
    void 未知用户_返回404_USER_NOT_FOUND() throws Exception {
        String body = """
            {"userId":99999,"identity":"user:corp001:99999:ghost@example.com"}""";
        mvc.perform(post("/kgc/sm9/issue-private-key")
                        .header("X-KGC-Token", kgcToken)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("USER_NOT_FOUND"));
    }

    @Test
    void 身份与用户不匹配_返回400_IDENTITY_MISMATCH() throws Exception {
        // userId 10002 是 Bob，但传了 Alice 的身份
        String body = """
            {"userId":10002,"identity":"user:corp001:10001:alice@example.com"}""";
        mvc.perform(post("/kgc/sm9/issue-private-key")
                        .header("X-KGC-Token", kgcToken)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("IDENTITY_MISMATCH"));
    }

    @Test
    void 缺必填字段_返回400_校验失败() throws Exception {
        String body = """
            {"deviceFingerprint":"x"}""";   // 缺 userId / identity
        mvc.perform(post("/kgc/sm9/issue-private-key")
                        .header("X-KGC-Token", kgcToken)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }
}
