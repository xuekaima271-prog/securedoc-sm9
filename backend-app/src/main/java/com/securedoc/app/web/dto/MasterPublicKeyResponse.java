package com.securedoc.app.web.dto;

/** SM9 主公钥（Base64, 64B），前端封装 DEK 用。经后端代理自 KGC 取得。 */
public record MasterPublicKeyResponse(String masterPublicKey) {}
