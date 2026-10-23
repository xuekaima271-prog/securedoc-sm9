package com.securedoc.kgc.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * kgc_private_key_issues —— KGC 私钥签发审计记录（设计文档 §2.2.6）。
 * 这是 SM9 在系统中落地的关键证据：每次签发/重新签发都留痕，可审计、不可抵赖。
 * 不存私钥本身，只记录「为谁、何时、何种类型、从何设备」签发。
 */
@Data
@TableName("kgc_private_key_issues")
public class KgcPrivateKeyIssue {

    @TableId(type = IdType.INPUT)         // UUID，应用层生成
    private String id;

    private Long userId;
    private String sm9Identity;
    private String issueType;             // FIRST / REISSUE
    private String deviceFingerprint;     // 浏览器设备指纹（可空）
    private String reason;                // 签发原因（重签发时填，如换设备）
    private Long operatorId;              // 操作人（自助签发即用户本人）
    private String clientIp;              // 请求 IP（兼容 IPv6）
    private String auditStatus;           // RECORDED / REVIEWED / REJECTED

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime issuedAt;
}
