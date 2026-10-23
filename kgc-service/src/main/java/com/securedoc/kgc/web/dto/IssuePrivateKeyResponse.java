package com.securedoc.kgc.web.dto;

/**
 * SM9 私钥签发响应（设计文档 §18.6.4）。
 * privateKeyPackage = Base64(de 128 字节)，前端收到后只在本地保存，绝不回传应用服务器。
 */
public record IssuePrivateKeyResponse(
        String issueId,
        Long userId,
        String identity,
        String privateKeyPackage,
        String issuedAt
) {}
