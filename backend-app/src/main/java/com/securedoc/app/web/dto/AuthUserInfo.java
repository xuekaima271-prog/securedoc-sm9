package com.securedoc.app.web.dto;

import java.util.List;

/** 当前登录用户信息（登录响应 / /me）。对应 §18.9.1：userId/username/roles/keyInitialized。 */
public record AuthUserInfo(
        Long userId,
        String username,
        List<String> roles,
        boolean keyInitialized
) {
}
