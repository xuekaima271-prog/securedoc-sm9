package com.securedoc.app.web.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * init-upload 中的单个接收人（§18.9.3）。keyEnvelope 为不透明 JSON（服务端原样存储，无法解封）。
 */
public record RecipientInput(
        @NotNull(message = "recipientId 不能为空") Long recipientId,
        @NotBlank(message = "recipientIdentity 不能为空") String recipientIdentity,
        @NotNull(message = "keyEnvelope 不能为空") JsonNode keyEnvelope
) {}
