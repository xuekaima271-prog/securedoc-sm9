package com.securedoc.app;

import com.securedoc.app.mapper.RoleMapper;
import com.securedoc.app.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** 管理员写操作（BE-7）：启停用户、改角色 + 负例（自操作/非法值/越权）。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AdminUserWriteTest {

    @Autowired MockMvc mvc;
    @Autowired UserMapper userMapper;
    @Autowired RoleMapper roleMapper;

    @Test
    @WithUserDetails("admin")
    void 禁用bob_状态变更且禁用后登录被拒() throws Exception {
        mvc.perform(put("/api/admin/users/10002/status")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"DISABLED\"}"))
                .andExpect(status().isOk());
        assertThat(userMapper.selectById(10002L).getStatus()).isEqualTo("DISABLED");

        // 禁用后即使密码正确也不能登录（DisabledException → USER_DISABLED）
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"username\":\"bob\",\"password\":\"Demo@123\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("USER_DISABLED"));
    }

    @Test
    @WithUserDetails("admin")
    void 改bob角色为审计员_生效() throws Exception {
        mvc.perform(put("/api/admin/users/10002/roles")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"roleCodes\":[\"SECURITY_AUDITOR\"]}"))
                .andExpect(status().isOk());
        assertThat(roleMapper.selectRoleCodesByUserId(10002L)).containsExactly("SECURITY_AUDITOR");
    }

    @Test
    @WithUserDetails("admin")
    void 管理员改自己状态_被拒() throws Exception {
        mvc.perform(put("/api/admin/users/10004/status")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"DISABLED\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    @WithUserDetails("admin")
    void 非法状态值_400() throws Exception {
        mvc.perform(put("/api/admin/users/10002/status")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"FOO\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    @WithUserDetails("admin")
    void 未知角色编码_400() throws Exception {
        mvc.perform(put("/api/admin/users/10002/roles")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"roleCodes\":[\"NOPE\"]}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    @WithUserDetails("alice")
    void 普通员工改状态_403() throws Exception {
        mvc.perform(put("/api/admin/users/10002/status")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"DISABLED\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PERMISSION_DENIED"));
    }
}
