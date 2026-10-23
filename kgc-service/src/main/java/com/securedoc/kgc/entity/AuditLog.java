package com.securedoc.kgc.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * audit_logs 通用审计（与 backend-app 共享表）。
 * KGC 把签发/重签发事件也写入通用审计流，便于 §2.10 的 KGC 签发日志查询统一展示。
 */
@Data
@TableName("audit_logs")
public class AuditLog {

    @TableId(type = IdType.AUTO)
    private Long id;

    private Long actorId;
    private String action;          // KGC_ISSUE / KGC_REISSUE
    private String resourceType;    // KGC
    private String resourceId;      // 签发记录 issueId
    private String clientIp;
    private String userAgent;
    private String detail;

    private String previousHash;    // SM3 哈希链预留（与 backend 一致，暂空）
    private String currentHash;

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;
}
