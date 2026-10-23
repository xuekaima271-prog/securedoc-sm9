package com.securedoc.app.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * files 文件投递主记录。命名为 FileRecord 以避开 java.io.File。
 * 安全：encryptedMetadata 是 SM4 加密后的元数据(含密文文件名)，服务端不存明文文件名。
 */
@Data
@TableName("files")
public class FileRecord {

    @TableId(type = IdType.INPUT)        // UUID，应用层生成
    private String id;

    private Long senderId;
    private String encryptedMetadata;    // TEXT JSON {algorithm,mode,iv,ciphertext,digest}
    private String ciphertextRootPath;   // encrypted-files/{fileId}
    private Long totalSize;
    private Integer chunkSize;
    private Integer chunkCount;
    private String status;               // INIT/UPLOADING/AVAILABLE/FAILED/DELETED

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;

    @TableField(fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updatedAt;
}
