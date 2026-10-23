package com.securedoc.app.web.dto;

import jakarta.validation.constraints.NotBlank;

/** 管理员改用户状态（§2.3）：ACTIVE/DISABLED/LOCKED。 */
public record UpdateUserStatusRequest(@NotBlank String status) {}
