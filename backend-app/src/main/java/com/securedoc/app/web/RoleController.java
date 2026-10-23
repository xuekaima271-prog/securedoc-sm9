package com.securedoc.app.web;

import com.securedoc.app.common.ApiResponse;
import com.securedoc.app.entity.Role;
import com.securedoc.app.mapper.RoleMapper;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** 角色查询（§2.3）。仅 SYS_ADMIN 可访问。 */
@RestController
@RequestMapping("/api")
public class RoleController {

    private final RoleMapper roleMapper;

    public RoleController(RoleMapper roleMapper) {
        this.roleMapper = roleMapper;
    }

    @GetMapping("/roles")
    @PreAuthorize("hasRole('SYS_ADMIN')")
    public ApiResponse<List<Role>> listRoles() {
        return ApiResponse.ok(roleMapper.selectList(null));
    }
}
