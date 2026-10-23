package com.securedoc.app.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

/** 管理员新增用户（§2.3）。email 必填：SM9 身份标识 user:corp001:{id}:{email} 的组成部分。 */
public record CreateUserRequest(
        @NotBlank @Size(min = 3, max = 32)
        @Pattern(regexp = "^[a-zA-Z][a-zA-Z0-9_]*$", message = "用户名须以字母开头，仅含字母/数字/下划线")
        String username,
        @NotBlank @Size(min = 8, max = 64, message = "密码至少 8 位") String password,
        @Size(max = 64) String realName,
        @NotBlank @Email @Size(max = 128) String email,
        @NotEmpty List<String> roleCodes
) {}
