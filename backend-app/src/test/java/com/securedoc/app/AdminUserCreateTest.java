package com.securedoc.app;

import com.securedoc.app.client.KgcClient;
import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.entity.User;
import com.securedoc.app.mapper.RoleMapper;
import com.securedoc.app.mapper.UserKeyMapper;
import com.securedoc.app.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * 管理员新增用户（§2.3）：创建→登录闭环、KGC 登记调用、KGC 失败回滚（一致性强负例）、
 * 重名/未知角色/弱密码 400、员工 403。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AdminUserCreateTest {

    @Autowired MockMvc mvc;
    @Autowired UserMapper userMapper;
    @Autowired UserKeyMapper userKeyMapper;
    @Autowired RoleMapper roleMapper;
    @MockitoBean KgcClient kgcClient;

    private static final String DAVE = """
        {"username":"dave","password":"Demo@123!","realName":"戴夫",
         "email":"dave@example.com","roleCodes":["EMPLOYEE"]}""";

    @Test
    @WithUserDetails("admin")
    void 创建dave_落库三表_身份格式正确_能登录() throws Exception {
        mvc.perform(post("/api/admin/users")
                        .contentType(MediaType.APPLICATION_JSON).content(DAVE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("dave"))
                .andExpect(jsonPath("$.data.keyStatus").value("UNINITIALIZED"));

        User dave = userMapper.selectByUsername("dave");
        assertThat(dave).isNotNull();
        assertThat(dave.getId()).isGreaterThanOrEqualTo(10006L);
        assertThat(dave.getPasswordHash()).startsWith("$2");   // BCrypt，非明文
        assertThat(roleMapper.selectRoleCodesByUserId(dave.getId())).containsExactly("EMPLOYEE");

        String expectedIdentity = "user:corp001:" + dave.getId() + ":dave@example.com";
        assertThat(userKeyMapper.selectByUserId(dave.getId()).getSm9Identity()).isEqualTo(expectedIdentity);
        Mockito.verify(kgcClient).registerIdentity(eq(dave.getId()), eq(expectedIdentity));

        // 新用户即可登录（完整旅程第一步）
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dave\",\"password\":\"Demo@123!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("dave"));
    }

    @Test
    @WithUserDetails("admin")
    // 挂起测试事务：让 service 的事务真实提交/回滚（类级测试事务会让 rollback-only 的数据在断言时仍可见）
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.NOT_SUPPORTED)
    void KGC登记失败_整体回滚_用户不存在() throws Exception {
        Mockito.doThrow(new BusinessException(ErrorCode.KGC_UNAVAILABLE))
                .when(kgcClient).registerIdentity(anyLong(), anyString());

        mvc.perform(post("/api/admin/users")
                        .contentType(MediaType.APPLICATION_JSON).content(DAVE))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("KGC_UNAVAILABLE"));

        assertThat(userMapper.selectByUsername("dave")).isNull();   // service 事务已真实回滚，两侧一致
    }

    @Test
    @WithUserDetails("admin")
    void 重名_400() throws Exception {
        mvc.perform(post("/api/admin/users").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                            {"username":"alice","password":"Demo@123!","email":"a2@example.com","roleCodes":["EMPLOYEE"]}"""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    @WithUserDetails("admin")
    void 未知角色_400() throws Exception {
        mvc.perform(post("/api/admin/users").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                            {"username":"dave2","password":"Demo@123!","email":"d2@example.com","roleCodes":["NOPE"]}"""))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithUserDetails("admin")
    void 弱密码_400() throws Exception {
        mvc.perform(post("/api/admin/users").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                            {"username":"dave3","password":"short","email":"d3@example.com","roleCodes":["EMPLOYEE"]}"""))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithUserDetails("alice")
    void 员工创建用户_403() throws Exception {
        mvc.perform(post("/api/admin/users")
                        .contentType(MediaType.APPLICATION_JSON).content(DAVE))
                .andExpect(status().isForbidden());
    }
}
