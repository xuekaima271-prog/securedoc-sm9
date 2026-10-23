package com.securedoc.app.web.dto;

/** 当前用户密钥状态（§2.10 GET /api/keys/me/status）。不含任何私钥。 */
public record KeyStatusResponse(
        Long userId,
        String identity,
        String keyStatus,      // UNINITIALIZED/ISSUED/REISSUED/REVOKED
        boolean deviceBound,
        boolean initialized    // keyStatus ∈ {ISSUED,REISSUED}
) {}
