package com.securedoc.app.web.dto;

/**
 * 密文分块下载结果（服务层 → 控制器）。data 为不透明密文字节；sm3Digest 为入库摘要，
 * 由控制器放入响应头 X-Chunk-Digest，浏览器解密前重算比对（账本 SM9-4 下载侧防篡改）。
 */
public record ChunkDownload(
        int chunkIndex,
        byte[] data,
        String sm3Digest,
        String ivNonce
) {}
