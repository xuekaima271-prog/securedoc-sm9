package com.securedoc.app.web.dto;

import java.util.List;

/** 管理员视角的用户摘要（不含 password_hash 等敏感字段）。 */
public record UserSummary(
        Long id,
        String username,
        String realName,
        String email,
        String status,
        List<String> roles,
        String keyStatus
) {
}
