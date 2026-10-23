package com.securedoc.app.web.dto;

/** 分块上传响应（§18.9.4）。 */
public record ChunkUploadResponse(String fileId, int chunkIndex, String status) {}
