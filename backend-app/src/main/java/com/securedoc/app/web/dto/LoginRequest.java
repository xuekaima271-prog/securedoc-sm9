package com.securedoc.app.web.dto;

import jakarta.validation.constraints.NotBlank;

/** 登录请求（对应 §18.9.1）。 */
public record LoginRequest(
        @NotBlank(message = "用户名不能为空") String username,
        @NotBlank(message = "密码不能为空") String password
) {
}
