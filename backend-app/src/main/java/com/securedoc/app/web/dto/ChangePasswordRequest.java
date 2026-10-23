package com.securedoc.app.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * 登录用户自助改密（H-1 补缺）。新密码强度与管理员建号口径一致（CreateUserRequest.password）：
 * 至少 8 位、至多 64 位；旧密码只做非空校验，正确性由服务端 BCrypt 比对。
 */
public record ChangePasswordRequest(
        @NotBlank String oldPassword,
        @NotBlank @Size(min = 8, max = 64, message = "密码至少 8 位") String newPassword
) {}
