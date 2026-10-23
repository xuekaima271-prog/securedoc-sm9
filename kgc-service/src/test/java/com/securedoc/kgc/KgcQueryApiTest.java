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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** 主公钥 / 身份 / 重签发 / 签发记录查询 接口集成测试。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class KgcQueryApiTest {

    @Autowired MockMvc mvc;
    @Value("${kgc.service-token}") String kgcToken;
    private final ObjectMapper om = new ObjectMapper();

    @Test
    void 主公钥_返回64字节base64() throws Exception {
        MvcResult res = mvc.perform(get("/kgc/sm9/master-public-key")
                        .header("X-KGC-Token", kgcToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.keyVersion").value(1))
                .andReturn();
        JsonNode root = om.readTree(res.getResponse().getContentAsString());
        byte[] pub = Base64.getDecoder().decode(root.path("data").path("masterPublicKey").asText());
        assertThat(pub).hasSize(64);
    }

    @Test
    void 查Bob身份() throws Exception {
        mvc.perform(get("/kgc/sm9/identity/10002").header("X-KGC-Token", kgcToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.identity").value("user:corp001:10002:bob@example.com"));
    }

    @Test
    void 查不存在用户身份_404() throws Exception {
        mvc.perform(get("/kgc/sm9/identity/99999").header("X-KGC-Token", kgcToken))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("USER_NOT_FOUND"));
    }

    @Test
    void 重新签发后能在签发记录里查到() throws Exception {
        String body = """
            {"userId":10002,"identity":"user:corp001:10002:bob@example.com","deviceFingerprint":"fp-new","reason":"换设备"}""";
        mvc.perform(post("/kgc/sm9/reissue-private-key")
                        .header("X-KGC-Token", kgcToken)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.identity").value("user:corp001:10002:bob@example.com"));

        // 按 userId 过滤查询签发记录，应至少 1 条且为 REISSUE
        MvcResult res = mvc.perform(get("/kgc/sm9/issues").param("userId", "10002")
                        .header("X-KGC-Token", kgcToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.total").value(org.hamcrest.Matchers.greaterThanOrEqualTo(1)))
                .andReturn();
        JsonNode records = om.readTree(res.getResponse().getContentAsString()).path("data").path("records");
        assertThat(records.isArray()).isTrue();
        assertThat(records.get(0).path("issueType").asText()).isEqualTo("REISSUE");
    }
}
