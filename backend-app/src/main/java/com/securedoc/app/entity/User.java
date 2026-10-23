package com.securedoc.app.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;
import lombok.ToString;

import java.time.LocalDateTime;

/** users 用户账号。password_hash 只存 BCrypt 哈希。 */
@Data
@TableName("users")
public class User {

    @TableId(type = IdType.AUTO)   // 自增（演示账号 10001 起，新用户 10006+）
    private Long id;

    private String username;

    @ToString.Exclude              // SEC-5：防止密码哈希经 toString 进日志
    private String passwordHash;
    private String realName;
    private String email;
    private Long departmentId;
    private String status;          // ACTIVE/DISABLED/LOCKED

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;

    @TableField(fill = FieldFill.INSERT_UPDATE)   // DB-4：插入与更新自动填充
    private LocalDateTime updatedAt;
}
