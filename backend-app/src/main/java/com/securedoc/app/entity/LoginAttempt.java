package com.securedoc.app.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/** login_attempts 登录失败聚合（每账号一行），用于账号锁定。MVP 无 Redis 的限流落库载体。 */
@Data
@TableName("login_attempts")
public class LoginAttempt {

    @TableId(type = IdType.AUTO)
    private Long id;

    private String username;
    private String clientIp;
    private Integer failCount;
    private LocalDateTime lockedUntil;
    private LocalDateTime lastFailedAt;

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;

    @TableField(fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updatedAt;
}
