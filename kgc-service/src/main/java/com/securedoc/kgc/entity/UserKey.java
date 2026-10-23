package com.securedoc.kgc.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * user_keys 用户 SM9 身份与密钥状态（KGC 侧读+更新视图）。
 * KGC 据此校验「请求身份是否与该用户绑定」，并在签发后把 keyStatus 推进为 ISSUED/REISSUED。
 * 不存私钥明文。
 */
@Data
@TableName("user_keys")
public class UserKey {

    @TableId(type = IdType.AUTO)
    private Long id;

    private Long userId;
    private String sm9Identity;
    private String keyStatus;       // UNINITIALIZED/ISSUED/REISSUED/REVOKED
    private Boolean deviceBound;
    private LocalDateTime lastIssueTime;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
