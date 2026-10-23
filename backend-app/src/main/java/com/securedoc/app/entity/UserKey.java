package com.securedoc.app.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/** user_keys 用户 SM9 身份标识与密钥状态。不存私钥明文。 */
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

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;

    @TableField(fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updatedAt;
}
