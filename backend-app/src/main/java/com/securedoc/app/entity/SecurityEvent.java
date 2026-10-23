package com.securedoc.app.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * security_events 安全事件（§2.2.12 安全事件告警）。
 * 由防线埋点自动生成；actor_id 逻辑外键（同 audit_logs 约定：须能记录未登录来源）。
 */
@Data
@TableName("security_events")
public class SecurityEvent {

    @TableId(type = IdType.AUTO)
    private Long id;

    private String eventType;   // BRUTE_FORCE_LOCK / IP_THROTTLED / ACCESS_DENIED / UNAUTHORIZED_FILE_ACCESS / CHUNK_TAMPER_DETECTED / OVERSIZED_CHUNK / AUDIT_CHAIN_BROKEN
    private String severity;    // HIGH / MEDIUM / LOW
    private Long actorId;       // 触发用户（可空：未登录暴力破解等）
    private String clientIp;
    private String resource;    // 相关资源（URI / fileId / 用户名）
    private String detail;

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;
}
