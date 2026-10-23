package com.securedoc.app.mapper.dto;

import lombok.Data;

/** 批量查询投影：用户ID -> 角色编码（避免逐用户查角色的 N+1）。 */
@Data
public class UserRoleCodeView {
    private Long userId;
    private String roleCode;
}
