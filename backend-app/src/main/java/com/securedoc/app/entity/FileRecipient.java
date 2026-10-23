package com.securedoc.app.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * file_recipients 文件接收人与 SM9 密钥信封（多人接收核心表）。
 * 安全：keyEnvelope 是 SM9 封装后的 SM4 文件密钥，服务端无法解封；接收人只能读自己的信封。
 */
@Data
@TableName("file_recipients")
public class FileRecipient {

    @TableId(type = IdType.AUTO)
    private Long id;

    private String fileId;
    private Long recipientId;
    private String recipientIdentity;    // 接收人 SM9 身份标识
    private String keyEnvelope;          // TEXT JSON {algorithm,wrappedKey,keyDigest,...}
    private String receiveStatus;        // PENDING/READ
    private String downloadStatus;       // NONE/DOWNLOADED/FAILED
    private LocalDateTime downloadedAt;

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;
}
