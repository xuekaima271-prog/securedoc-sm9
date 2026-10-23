package com.securedoc.kgc.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * SM9 私钥签发/重新签发请求（设计文档 §18.9.2）。
 * reason 仅重新签发时有意义（如「更换设备」）。
 */
public record IssuePrivateKeyRequest(
        @NotNull(message = "userId 不能为空") Long userId,
        @NotBlank(message = "identity 不能为空") String identity,
        String deviceFingerprint,
        String reason
) {}
