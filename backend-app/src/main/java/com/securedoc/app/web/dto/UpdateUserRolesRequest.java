package com.securedoc.app.web.dto;

import jakarta.validation.constraints.NotEmpty;

import java.util.List;

/** 管理员改用户角色（§2.3）：整集替换为给定角色编码。 */
public record UpdateUserRolesRequest(@NotEmpty List<String> roleCodes) {}
