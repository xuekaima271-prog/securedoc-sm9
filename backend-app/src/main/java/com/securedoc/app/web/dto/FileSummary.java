package com.securedoc.app.web.dto;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * 收件箱/发件箱列表项。encryptedMetadata 原样回传（前端解密展示文件名）；不含任何明文或密钥。
 */
public record FileSummary(
        String fileId,
        Long senderId,
        JsonNode encryptedMetadata,
        String status,
        Long totalSize,
        Integer chunkSize,
        Integer chunkCount,
        String createdAt
) {}
