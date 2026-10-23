package com.securedoc.app;

import com.securedoc.app.service.LoginThrottleService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Step 3.5 登录限流测试：账号锁定、成功重置、IP 维度限流(防账号锁定 DoS / DB-2)。
 * 每个用例前后 clearAll，避免限流状态跨用例/跨测试类污染。
 */
@SpringBootTest
@AutoConfigureMockMvc
class LoginThrottleTests {

    @Autowired MockMvc mvc;
    @Autowired LoginThrottleService throttle;

    @BeforeEach
    @AfterEach
    void clean() {
        throttle.clearAll();
    }

    private ResultActions login(String user, String pwd, String ip) throws Exception {
        return mvc.perform(post("/api/auth/login")
                .with(r -> { r.setRemoteAddr(ip); return r; })
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + user + "\",\"password\":\"" + pwd + "\"}"));
    }

    @Test
    void 连续5次错密码后账号锁定_即使密码正确也被拒() throws Exception {
        for (int i = 0; i < 5; i++) {
            login("carol", "wrong", "1.1.1.1").andExpect(status().isUnauthorized());
        }
        // 第 6 次即使密码正确，也因账号锁定被拒
        login("carol", "Demo@123", "1.1.1.1")
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("RATE_LIMITED"));
    }

    @Test
    void 成功登录重置失败计数() throws Exception {
        for (int i = 0; i < 4; i++) {                          // 4 次 < 阈值5，未锁
            login("carol", "wrong", "1.1.1.2").andExpect(status().isUnauthorized());
        }
        login("carol", "Demo@123", "1.1.1.2").andExpect(status().isOk());   // 成功 → 重置
        for (int i = 0; i < 4; i++) {                          // 重置后再错 4 次仍不锁
            login("carol", "wrong", "1.1.1.2").andExpect(status().isUnauthorized());
        }
        login("carol", "Demo@123", "1.1.1.2").andExpect(status().isOk());
    }

    @Test
    void 同一IP失败过多被限流_防账号锁定DoS() throws Exception {
        // 用不同(不存在)用户名，避免触发单账号锁定，专测 IP 维度
        for (int i = 0; i < 10; i++) {
            login("ghost" + i, "x", "9.9.9.9").andExpect(status().isUnauthorized());
        }
        // 第 11 次(再换个用户名)该 IP 已被限流
        login("ghostX", "x", "9.9.9.9")
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("RATE_LIMITED"));
    }
}
