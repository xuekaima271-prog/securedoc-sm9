package com.securedoc.app.web.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;

/**
 * 初始化上传请求（§18.9.3）。encryptedMetadata 为不透明 JSON（SM4 加密后的文件名等，服务端原样存储）。
 * chunkCount/totalSize 这里只做下限校验；总量上限（app.upload.* 配置）与三者一致性由
 * FileUploadService.init 在落库前校验（M-2，阈值需可配置，故不写死在注解上）。
 */
public record InitUploadRequest(
        @NotNull(message = "encryptedMetadata 不能为空") JsonNode encryptedMetadata,
        @NotNull @Min(value = 1, message = "chunkSize 必须为正") Integer chunkSize,
        @NotNull @Min(value = 1, message = "chunkCount 必须为正") Integer chunkCount,
        @NotNull @Min(value = 0, message = "totalSize 不能为负") Long totalSize,
        @NotEmpty(message = "至少一个接收人") @Valid List<RecipientInput> recipients
) {}
