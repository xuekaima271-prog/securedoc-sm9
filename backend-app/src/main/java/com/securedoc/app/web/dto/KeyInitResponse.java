package com.securedoc.app.web.dto;

/**
 * 密钥初始化响应（§18.6.4）。privateKeyPackage 仅中转给浏览器存 IndexedDB，
 * 应用服务器不持久化它。
 */
public record KeyInitResponse(
        Long userId,
        String identity,
        String privateKeyPackage,
        String issueId,
        String issuedAt
) {}
