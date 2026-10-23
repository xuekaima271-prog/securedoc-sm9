package com.securedoc.app.web.dto;

/** 可选接收人（§6 GET /api/keys/recipients）：发送页选人用。仅身份标识与密钥状态，无私钥。 */
public record RecipientView(
        Long userId,
        String username,
        String realName,
        String identity,
        String keyStatus
) {}
