package com.securedoc.app.service;

import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.entity.User;
import com.securedoc.app.mapper.UserMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 账号自助服务（H-1 补缺：此前全系统无改密接口，种子口令 Demo@123 一旦泄露无从补救）。
 * 改密规则：必须先验证旧密码；新密码不得与旧密码相同（强度下限由 DTO 校验，与建号同口径）。
 * 会话失效由调用方（AuthController）在本方法成功返回后处理：作废当前会话并要求用新密码重新登录。
 * 架构限制（如实记录）：当前会话为容器内存 HttpSession、无全局 SessionRegistry，无法枚举并
 * 作废该用户在其他设备上的既有会话；那些会话只能等其自然过期，但任何新登录都必须用新密码。
 * 若后续引入 SessionRegistry/spring-session，再在此处补全量下线。
 */
@Service
public class AccountService {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    public AccountService(UserMapper userMapper, PasswordEncoder passwordEncoder, AuditService auditService) {
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
    }

    /** 修改当前登录用户自己的密码。旧密码错误抛 INVALID_CREDENTIALS(401)，与登录失败同一口径。 */
    @Transactional
    public void changePassword(Long userId, String oldPassword, String newPassword, String clientIp) {
        User u = userMapper.selectById(userId);
        if (u == null) {
            throw new BusinessException(ErrorCode.AUTH_REQUIRED);
        }
        if (!passwordEncoder.matches(oldPassword, u.getPasswordHash())) {
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS, "旧密码不正确");
        }
        if (passwordEncoder.matches(newPassword, u.getPasswordHash())) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "新密码不能与旧密码相同");
        }
        u.setPasswordHash(passwordEncoder.encode(newPassword));
        userMapper.updateById(u);
        auditService.record(userId, "PASSWORD_CHANGE", "USER", String.valueOf(userId), clientIp, null,
                "用户修改登录密码，当前会话已失效，须用新密码重新登录");
    }
}
