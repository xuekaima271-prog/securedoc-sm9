package com.securedoc.kgc.web.dto;

/**
 * 主公钥响应：masterPublicKey = Base64(Ppub_e 64 字节 = x||y)。
 * 发送方据此对接收人身份做 SM9 IBE 封装；公开信息，可不鉴权获取。
 */
public record MasterPublicKeyResponse(
        String masterPublicKey,
        int keyVersion
) {}
