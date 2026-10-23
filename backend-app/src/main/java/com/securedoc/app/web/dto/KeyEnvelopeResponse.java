package com.securedoc.app.web.dto;

import com.fasterxml.jackson.databind.JsonNode;

/** 密钥信封响应（§18.9.5）。keyEnvelope 为 SM9 封装的 SM4 文件密钥，仅接收人本人可取。 */
public record KeyEnvelopeResponse(
        String fileId,
        String recipientIdentity,
        JsonNode keyEnvelope
) {}
