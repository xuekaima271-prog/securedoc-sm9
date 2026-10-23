package com.securedoc.kgc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Step8 鉴权 + 身份格式校验 测试。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class KgcSecurityApiTest {

    @Autowired MockMvc mvc;
    @Value("${kgc.service-token}") String kgcToken;

    private static final String BOB = """
        {"userId":10002,"identity":"user:corp001:10002:bob@example.com"}""";

    @Test
    void 签发接口缺令牌_401() throws Exception {
        mvc.perform(post("/kgc/sm9/issue-private-key")
                        .contentType(MediaType.APPLICATION_JSON).content(BOB))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("KGC_UNAUTHORIZED"));
    }

    @Test
    void 签发接口令牌错误_401() throws Exception {
        mvc.perform(post("/kgc/sm9/issue-private-key")
                        .header("X-KGC-Token", "wrong-token")
                        .contentType(MediaType.APPLICATION_JSON).content(BOB))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("KGC_UNAUTHORIZED"));
    }

    @Test
    void 签发接口令牌正确_200() throws Exception {
        mvc.perform(post("/kgc/sm9/issue-private-key")
                        .header("X-KGC-Token", kgcToken)
                        .contentType(MediaType.APPLICATION_JSON).content(BOB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void 主公钥接口缺令牌_401() throws Exception {
        mvc.perform(get("/kgc/sm9/master-public-key"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("KGC_UNAUTHORIZED"));
    }

    @Test
    void 主公钥接口令牌正确_200() throws Exception {
        mvc.perform(get("/kgc/sm9/master-public-key")
                        .header("X-KGC-Token", kgcToken))
                .andExpect(status().isOk());
    }

    @Test
    void 主公钥接口路径变体仍需令牌() throws Exception {
        mvc.perform(get("/kgc/sm9;ignored/master-public-key"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("KGC_UNAUTHORIZED"));
    }

    @Test
    void 健康检查公开_免令牌200() throws Exception {
        mvc.perform(get("/kgc/health"))
                .andExpect(status().isOk());
    }

    @Test
    void 非法身份格式_400_IDENTITY_INVALID() throws Exception {
        String bad = """
            {"userId":10002,"identity":"not-a-valid-identity"}""";
        mvc.perform(post("/kgc/sm9/issue-private-key")
                        .header("X-KGC-Token", kgcToken)
                        .contentType(MediaType.APPLICATION_JSON).content(bad))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("IDENTITY_INVALID"));
    }
}
