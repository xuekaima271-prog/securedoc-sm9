package com.securedoc.kgc.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * 身份登记请求（新用户开通）。由应用服务器在创建用户时调用（X-KGC-Token 信任边界），
 * 把 userId 与 SM9 身份标识登记进 KGC 名单，之后该用户才能签发私钥。
 */
public record RegisterIdentityRequest(
        @NotNull(message = "userId 不能为空") Long userId,
        @NotBlank(message = "identity 不能为空") String identity
) {}
