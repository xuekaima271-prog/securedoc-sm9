package com.securedoc.app.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * file_chunks 文件密文分块记录。sm3Digest 为该块密文的 SM3 摘要(base64)，下载时重算比对防篡改(SM9-4)。
 */
@Data
@TableName("file_chunks")
public class FileChunk {

    @TableId(type = IdType.AUTO)
    private Long id;

    private String fileId;
    private Integer chunkIndex;          // 0 起
    private String objectKey;            // encrypted-files/{fileId}/chunk-{index}.bin
    private Integer chunkSize;
    private String sm3Digest;            // 密文分块 SM3 摘要(base64)
    private String ivNonce;              // 该块 IV/Nonce(base64)
    private String authTag;              // AEAD 认证标签(可空)
    private String uploadStatus;         // PENDING/UPLOADED/FAILED

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;
}
