package com.securedoc.app.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/** audit_logs 审计日志。previousHash/currentHash 为哈希链：v2 起 currentHash 带 "v2$" 前缀（HMAC-SM3，M-3），无前缀为 v1 存量无钥 SM3。 */
@Data
@TableName("audit_logs")
public class AuditLog {

    @TableId(type = IdType.AUTO)
    private Long id;

    private Long actorId;          // 操作人(可空=系统/未知，如登录失败的不存在用户)
    private String action;         // LOGIN / LOGOUT / LOGIN_FAIL / ...(后续 FILE_UPLOAD/KGC_ISSUE 等)
    private String resourceType;   // AUTH / FILE / USER ...
    private String resourceId;
    private String clientIp;
    private String userAgent;
    private String detail;         // TEXT(H2=CLOB)；DB-3 验证点

    private String previousHash;   // 哈希链预留（Step8）
    private String currentHash;

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;
}
