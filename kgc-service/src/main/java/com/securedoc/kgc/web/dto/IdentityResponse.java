package com.securedoc.kgc.web.dto;

/** 用户 SM9 身份标识响应（设计文档 §2.4 GET /kgc/sm9/identity/{userId}）。 */
public record IdentityResponse(
        Long userId,
        String identity
) {}
