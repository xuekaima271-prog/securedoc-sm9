package com.securedoc.app;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Step 3.4 RBAC 测试：SYS_ADMIN 通过，EMPLOYEE 403，未登录 401。 */
@SpringBootTest
@AutoConfigureMockMvc
class AdminControllerTests {

    @Autowired
    MockMvc mvc;

    @Test
    @WithMockUser(username = "admin", roles = {"SYS_ADMIN"})
    void 管理员可查用户列表() throws Exception {
        mvc.perform(get("/api/admin/users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.length()").value(5))
                .andExpect(jsonPath("$.data[0].roles").isArray());
    }

    @Test
    @WithMockUser(username = "alice", roles = {"EMPLOYEE"})
    void 普通员工查用户列表_403_PERMISSION_DENIED() throws Exception {
        mvc.perform(get("/api/admin/users"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PERMISSION_DENIED"));
    }

    @Test
    void 未登录查用户列表_401_AUTH_REQUIRED() throws Exception {
        mvc.perform(get("/api/admin/users"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTH_REQUIRED"));
    }

    @Test
    @WithMockUser(roles = {"SYS_ADMIN"})
    void 管理员可查角色列表_5个() throws Exception {
        mvc.perform(get("/api/roles"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(5));
    }

    @Test
    @WithMockUser(roles = {"EMPLOYEE"})
    void 普通员工查角色列表_403() throws Exception {
        mvc.perform(get("/api/roles"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PERMISSION_DENIED"));
    }
}
