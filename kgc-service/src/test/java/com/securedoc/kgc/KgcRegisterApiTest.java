package com.securedoc.kgc;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.securedoc.kgc.entity.UserKey;
import com.securedoc.kgc.mapper.UserKeyMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * 身份登记接口 POST /kgc/sm9/register-identity（新用户开通）：
 * 登记→可签发（新用户闭环核心）、幂等、身份不可改写、内嵌 userId 校验、占用冲突、格式、令牌。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class KgcRegisterApiTest {

    @Autowired MockMvc mvc;
    @Autowired UserKeyMapper userKeyMapper;
    @Value("${kgc.service-token}") String kgcToken;

    private static final String DAVE_ID = "user:corp001:20001:dave@example.com";

    private org.springframework.test.web.servlet.ResultActions register(String body) throws Exception {
        return mvc.perform(post("/kgc/sm9/register-identity")
                .header("X-KGC-Token", kgcToken)
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    @Test
    void 登记新身份_落库UNINITIALIZED_且随后可签发私钥() throws Exception {
        register("{\"userId\":20001,\"identity\":\"" + DAVE_ID + "\"}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.identity").value(DAVE_ID));

        UserKey uk = userKeyMapper.selectOne(new LambdaQueryWrapper<UserKey>().eq(UserKey::getUserId, 20001L));
        assertThat(uk).isNotNull();
        assertThat(uk.getKeyStatus()).isEqualTo("UNINITIALIZED");

        // 登记后即可签发（新用户闭环）：此前未登记用户签发会 404
        mvc.perform(post("/kgc/sm9/issue-private-key")
                        .header("X-KGC-Token", kgcToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userId\":20001,\"identity\":\"" + DAVE_ID + "\",\"deviceFingerprint\":\"fp\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.privateKeyPackage").isNotEmpty());
    }

    @Test
    void 重复登记同身份_幂等成功() throws Exception {
        register("{\"userId\":20001,\"identity\":\"" + DAVE_ID + "\"}").andExpect(status().isOk());
        register("{\"userId\":20001,\"identity\":\"" + DAVE_ID + "\"}").andExpect(status().isOk());
        assertThat(userKeyMapper.selectCount(new LambdaQueryWrapper<UserKey>().eq(UserKey::getUserId, 20001L)))
                .isEqualTo(1);
    }

    @Test
    void 同用户改写不同身份_400_IDENTITY_MISMATCH() throws Exception {
        register("{\"userId\":20001,\"identity\":\"" + DAVE_ID + "\"}").andExpect(status().isOk());
        register("{\"userId\":20001,\"identity\":\"user:corp001:20001:evil@example.com\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("IDENTITY_MISMATCH"));
    }

    @Test
    void 内嵌userId与请求不一致_400() throws Exception {
        // 请求 userId=20002，但 identity 内嵌 20001 → 防为他人登记
        register("{\"userId\":20002,\"identity\":\"" + DAVE_ID + "\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("IDENTITY_MISMATCH"));
    }

    @Test
    void 身份格式非法_400_IDENTITY_INVALID() throws Exception {
        register("{\"userId\":20001,\"identity\":\"not-an-identity\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("IDENTITY_INVALID"));
    }

    @Test
    void 无令牌_401() throws Exception {
        mvc.perform(post("/kgc/sm9/register-identity")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userId\":20001,\"identity\":\"" + DAVE_ID + "\"}"))
                .andExpect(status().isUnauthorized());
    }
}
