package com.securedoc.app.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** 密钥初始化请求（可选设备指纹，用于换设备重签发审计）。 */
public record KeyInitRequest(
        @Size(max = 255) String deviceFingerprint,
        @NotBlank @Size(max = 64) String password
) {
    @Override
    public String toString() {
        return "KeyInitRequest[credentials redacted]";
    }
}
