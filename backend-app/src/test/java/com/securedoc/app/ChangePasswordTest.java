package com.securedoc.app;

import com.securedoc.app.entity.User;
import com.securedoc.app.mapper.UserMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * H-1 自助改密：成功改密后当前会话失效、新密码可登录/旧密码被拒；旧密码错误被拒且不影响会话与原密码；
 * 新旧相同、新密码过短、未登录均被拒。用一次性账号 + 事务回滚，避免污染其他用例的种子账号。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ChangePasswordTest {

    @Autowired MockMvc mvc;
    @Autowired UserMapper userMapper;
    @Autowired PasswordEncoder passwordEncoder;

    private static final String OLD_PWD = "OldPass@123";
    private static final String NEW_PWD = "NewPass@456";

    @BeforeEach
    void seedUser() {
        User u = new User();
        u.setUsername("pwd_tester");
        u.setPasswordHash(passwordEncoder.encode(OLD_PWD));
        u.setRealName("改密测试号");
        u.setEmail("pwd_tester@example.com");
        u.setStatus("ACTIVE");
        userMapper.insert(u);
    }

    private MockHttpSession login(String password) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"pwd_tester\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    private String changeBody(String oldPwd, String newPwd) {
        return "{\"oldPassword\":\"" + oldPwd + "\",\"newPassword\":\"" + newPwd + "\"}";
    }

    @Test
    void 改密成功_当前会话失效_新密码可登录旧密码被拒() throws Exception {
        MockHttpSession session = login(OLD_PWD);

        mvc.perform(post("/api/auth/change-password").session(session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(changeBody(OLD_PWD, NEW_PWD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        assertThat(session.isInvalid()).isTrue();   // 改密后当前会话立即作废

        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"pwd_tester\",\"password\":\"" + OLD_PWD + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        login(NEW_PWD);   // 新密码可登录（内部断言 200）
    }

    @Test
    void 旧密码错误_返回401_会话与原密码不受影响() throws Exception {
        MockHttpSession session = login(OLD_PWD);

        mvc.perform(post("/api/auth/change-password").session(session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(changeBody("WrongOld@1", NEW_PWD)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));

        mvc.perform(get("/api/auth/me").session(session))   // 会话仍有效
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("pwd_tester"));
        login(OLD_PWD);   // 原密码仍可登录
    }

    @Test
    void 新密码与旧密码相同_返回400() throws Exception {
        MockHttpSession session = login(OLD_PWD);
        mvc.perform(post("/api/auth/change-password").session(session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(changeBody(OLD_PWD, OLD_PWD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    void 新密码过短_返回400() throws Exception {
        MockHttpSession session = login(OLD_PWD);
        mvc.perform(post("/api/auth/change-password").session(session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(changeBody(OLD_PWD, "Ab1@567")))   // 7 位 < 建号口径 8 位
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    void 未登录改密_返回401() throws Exception {
        mvc.perform(post("/api/auth/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(changeBody(OLD_PWD, NEW_PWD)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTH_REQUIRED"));
    }
}
