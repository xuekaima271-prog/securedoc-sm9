package com.securedoc.app.web.dto;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/**
 * 管理员密文记录视图（§2.9 / §2.10 GET /api/admin/files）。
 * 安全红线：encryptedMetadata 仍是 SM4 加密后的元数据（含密文文件名），管理员看不到明文；
 * 不含任何 SM4 密钥/SM9 私钥/密钥信封内容——以此证明「管理员可审计、不可解密」。
 */
public record AdminFileView(
        String fileId,
        Long senderId,
        String status,
        Long totalSize,
        Integer chunkSize,
        Integer chunkCount,
        int recipientCount,
        List<Long> recipientIds,
        JsonNode encryptedMetadata,   // 密文，证明管理员不可解
        String createdAt
) {}
