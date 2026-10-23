package com.securedoc.app;

import com.securedoc.app.client.KgcClient;
import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.entity.Role;
import com.securedoc.app.entity.User;
import com.securedoc.app.entity.UserRole;
import com.securedoc.app.mapper.RoleMapper;
import com.securedoc.app.mapper.UserMapper;
import com.securedoc.app.mapper.UserRoleMapper;
import com.securedoc.app.service.AdminUserService;
import com.securedoc.app.web.dto.CreateUserRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 权限分级（2026-10-23）：SUPER_ADMIN 任免管理员、普通 SYS_ADMIN 越权被拒、
 * "最后一个管理员"保底。种子 admin(10004) 持 SYS_ADMIN+SUPER_ADMIN；
 * 普通管理员场景用直查 DB 的方式给 bob(10002) 临时授予 SYS_ADMIN 再以操作者身份调用服务层
 * （服务层规则只认操作者 ID，与安全上下文无关，故直调 AdminUserService 验证）。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AdminPrivilegeTest {

    @Autowired MockMvc mvc;
    @Autowired UserMapper userMapper;
    @Autowired RoleMapper roleMapper;
    @Autowired UserRoleMapper userRoleMapper;
    @Autowired AdminUserService adminUserService;
    @MockitoBean KgcClient kgcClient;

    private static final long ALICE = 10001L;
    private static final long BOB = 10002L;
    private static final long CAROL = 10003L;
    private static final long ADMIN = 10004L;
    private static final String IP = "127.0.0.1";

    /** 直查 DB 给用户加一个角色（测试夹具，不走被测的任免规则）。 */
    private void grantRole(long userId, String roleCode) {
        Long roleId = roleMapper.selectList(null).stream()
                .filter(r -> r.getRoleCode().equals(roleCode))
                .map(Role::getId).findFirst().orElseThrow();
        UserRole ur = new UserRole();
        ur.setUserId(userId);
        ur.setRoleId(roleId);
        userRoleMapper.insert(ur);
    }

    private void setStatus(long userId, String status) {
        User u = userMapper.selectById(userId);
        u.setStatus(status);
        userMapper.updateById(u);
    }

    // ---------- 超管任免：成功路径（HTTP 层） ----------

    @Test
    @WithUserDetails("admin")
    void 超管授予bob系统管理员_成功() throws Exception {
        mvc.perform(put("/api/admin/users/10002/roles")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roleCodes\":[\"EMPLOYEE\",\"SYS_ADMIN\"]}"))
                .andExpect(status().isOk());
        assertThat(roleMapper.selectRoleCodesByUserId(BOB)).contains("SYS_ADMIN");
    }

    @Test
    @WithUserDetails("admin")
    void 超管撤销bob系统管理员_成功() throws Exception {
        grantRole(BOB, "SYS_ADMIN");
        mvc.perform(put("/api/admin/users/10002/roles")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"roleCodes\":[\"EMPLOYEE\"]}"))
                .andExpect(status().isOk());
        assertThat(roleMapper.selectRoleCodesByUserId(BOB)).containsExactly("EMPLOYEE");
    }

    @Test
    @WithUserDetails("admin")
    void 超管创建管理员账号_成功() throws Exception {
        mvc.perform(post("/api/admin/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                            {"username":"root2","password":"Demo@123!","realName":"副管理员",
                             "email":"root2@example.com","roleCodes":["SYS_ADMIN"]}"""))
                .andExpect(status().isOk());
        User root2 = userMapper.selectByUsername("root2");
        assertThat(root2).isNotNull();
        assertThat(roleMapper.selectRoleCodesByUserId(root2.getId())).containsExactly("SYS_ADMIN");
    }

    @Test
    @WithUserDetails("admin")
    void 超管停用普通管理员_成功_保底不误伤() throws Exception {
        grantRole(BOB, "SYS_ADMIN");   // 此时可用管理员为 admin+bob 共 2 个
        mvc.perform(put("/api/admin/users/10002/status")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"DISABLED\"}"))
                .andExpect(status().isOk());
        assertThat(userMapper.selectById(BOB).getStatus()).isEqualTo("DISABLED");
    }

    // ---------- 最后一个管理员保底（HTTP 层） ----------

    @Test
    @WithUserDetails("admin")
    void 停用最后一个管理员_400() throws Exception {
        grantRole(BOB, "SYS_ADMIN");
        setStatus(ADMIN, "DISABLED");   // 夹具：admin 在库中已停用，可用管理员只剩 bob（会话凭据已在测试上下文建立，不受影响）
        mvc.perform(put("/api/admin/users/10002/status")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"DISABLED\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        assertThat(userMapper.selectById(BOB).getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    @WithUserDetails("admin")
    void 降级最后一个管理员_400() throws Exception {
        grantRole(BOB, "SYS_ADMIN");
        setStatus(ADMIN, "DISABLED");
        mvc.perform(put("/api/admin/users/10002/roles")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"roleCodes\":[\"EMPLOYEE\"]}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        assertThat(roleMapper.selectRoleCodesByUserId(BOB)).contains("SYS_ADMIN");
    }

    // ---------- 普通管理员越权：服务层被拒 ----------

    @Test
    void 普通管理员授予他人管理员角色_被拒() {
        grantRole(BOB, "SYS_ADMIN");
        assertThatThrownBy(() -> adminUserService.updateRoles(BOB, CAROL, List.of("SYS_ADMIN"), IP))
                .isInstanceOfSatisfying(BusinessException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.PERMISSION_DENIED));
        assertThat(roleMapper.selectRoleCodesByUserId(CAROL)).containsExactly("EMPLOYEE");
    }

    @Test
    void 普通管理员修改管理员账号角色_被拒() {
        grantRole(BOB, "SYS_ADMIN");
        assertThatThrownBy(() -> adminUserService.updateRoles(BOB, ADMIN, List.of("EMPLOYEE"), IP))
                .isInstanceOfSatisfying(BusinessException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.PERMISSION_DENIED));
        assertThat(roleMapper.selectRoleCodesByUserId(ADMIN))
                .containsExactlyInAnyOrder("SYS_ADMIN", "SUPER_ADMIN");
    }

    @Test
    void 普通管理员停用管理员账号_被拒() {
        grantRole(BOB, "SYS_ADMIN");
        assertThatThrownBy(() -> adminUserService.updateStatus(BOB, ADMIN, "DISABLED", IP))
                .isInstanceOfSatisfying(BusinessException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.PERMISSION_DENIED));
        assertThat(userMapper.selectById(ADMIN).getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void 普通管理员创建管理员账号_被拒() {
        grantRole(BOB, "SYS_ADMIN");
        CreateUserRequest req = new CreateUserRequest(
                "mallory", "Demo@123!", "马洛里", "mallory@example.com", List.of("SYS_ADMIN"));
        assertThatThrownBy(() -> adminUserService.createUser(BOB, req, IP))
                .isInstanceOfSatisfying(BusinessException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.PERMISSION_DENIED));
        assertThat(userMapper.selectByUsername("mallory")).isNull();
    }

    @Test
    void 普通管理员管理普通用户_成功_正控() {
        grantRole(BOB, "SYS_ADMIN");
        adminUserService.updateStatus(BOB, ALICE, "DISABLED", IP);
        assertThat(userMapper.selectById(ALICE).getStatus()).isEqualTo("DISABLED");
        adminUserService.updateRoles(BOB, CAROL, List.of("SECURITY_AUDITOR"), IP);
        assertThat(roleMapper.selectRoleCodesByUserId(CAROL)).containsExactly("SECURITY_AUDITOR");
    }
}
