package com.securedoc.app.web.dto;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/**
 * 收件箱/发件箱列表项。encryptedMetadata 原样回传（前端解密展示文件名）；不含任何明文或密钥。
 * recipientIds 为全部接收人用户 id（发件箱「接收人」列数据源，前端再映射为显示名）；
 * 与管理员视图 AdminFileView 的同名字段口径一致。
 */
public record FileSummary(
        String fileId,
        Long senderId,
        JsonNode encryptedMetadata,
        String status,
        Long totalSize,
        Integer chunkSize,
        Integer chunkCount,
        String createdAt,
        List<Long> recipientIds
) {}
