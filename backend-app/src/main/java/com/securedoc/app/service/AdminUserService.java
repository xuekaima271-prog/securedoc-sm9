package com.securedoc.app.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.securedoc.app.client.KgcClient;
import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.entity.Role;
import com.securedoc.app.entity.User;
import com.securedoc.app.entity.UserKey;
import com.securedoc.app.entity.UserRole;
import com.securedoc.app.mapper.RoleMapper;
import com.securedoc.app.mapper.UserKeyMapper;
import com.securedoc.app.mapper.UserMapper;
import com.securedoc.app.mapper.UserRoleMapper;
import com.securedoc.app.mapper.dto.UserRoleCodeView;
import com.securedoc.app.web.dto.CreateUserRequest;
import com.securedoc.app.web.dto.UserSummary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 管理员用户视图装配 + 写操作（新增 / 启停 / 改角色，§2.3，BE-7）。
 * 权限分级（2026-10-23）：新增 SUPER_ADMIN 超级管理员——只有超管能授予/撤销管理员类角色、
 * 能修改管理员账号的角色与状态；普通 SYS_ADMIN 只能管理非管理员账号。
 * 系统级保底：可用管理员（ACTIVE 且持 SYS_ADMIN/SUPER_ADMIN）至少保留 1 个，最后一个不可降权/停用。
 */
@Service
public class AdminUserService {

    private static final Logger log = LoggerFactory.getLogger(AdminUserService.class);
    private static final Set<String> VALID_STATUS = Set.of("ACTIVE", "DISABLED", "LOCKED");
    private static final String ROLE_SUPER_ADMIN = "SUPER_ADMIN";
    /** 管理员类角色：任免受超管专属与"最后一个管理员"保底约束。 */
    private static final Set<String> ADMIN_ROLES = Set.of("SYS_ADMIN", "SUPER_ADMIN");
    /** SM9 身份租户段（与 init_data 种子一致）。 */
    private static final String TENANT = "corp001";

    private final UserMapper userMapper;
    private final UserRoleMapper userRoleMapper;
    private final UserKeyMapper userKeyMapper;
    private final RoleMapper roleMapper;
    private final AuditService auditService;
    private final PasswordEncoder passwordEncoder;
    private final KgcClient kgcClient;
    private final TransactionTemplate txTemplate;

    public AdminUserService(UserMapper userMapper, UserRoleMapper userRoleMapper, UserKeyMapper userKeyMapper,
                            RoleMapper roleMapper, AuditService auditService,
                            PasswordEncoder passwordEncoder, KgcClient kgcClient, TransactionTemplate txTemplate) {
        this.userMapper = userMapper;
        this.userRoleMapper = userRoleMapper;
        this.userKeyMapper = userKeyMapper;
        this.roleMapper = roleMapper;
        this.auditService = auditService;
        this.passwordEncoder = passwordEncoder;
        this.kgcClient = kgcClient;
        this.txTemplate = txTemplate;
    }

    /**
     * 新增用户（§2.3，USER-1 加固后的 Saga 补偿模式）：
     *   阶段1（本地事务，提交）：建账号(BCrypt) + 分配角色 + 生成 SM9 身份 user:corp001:{id}:{email}
     *   阶段2（事务外远程调用）：登记到 KGC 身份名单
     *   补偿：阶段2 失败 → 删除阶段1 落库的三表数据 + 审计 USER_CREATE_FAIL → 原样抛出
     * 为什么不把 KGC RPC 放事务内：Step11 真 MySQL 共库实证——KGC 读不到未提交行会走影子行插入，
     * 撞本事务行锁形成分布式死锁（HTTP 等 DB、DB 等 HTTP）。先提交后登记在任何拓扑下都无此窗口；
     * KGC 登记幂等，重试安全；补偿删除保证两侧名单最终一致。
     */
    public UserSummary createUser(Long adminId, CreateUserRequest req, String clientIp) {
        if (userMapper.selectByUsername(req.username()) != null) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "用户名已存在: " + req.username());
        }
        Map<String, Long> roleIdByCode = roleMapper.selectList(null).stream()
                .collect(Collectors.toMap(Role::getRoleCode, Role::getId));
        List<String> roles = req.roleCodes().stream().distinct().toList();
        List<String> unknown = roles.stream().filter(c -> !roleIdByCode.containsKey(c)).toList();
        if (!unknown.isEmpty()) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "未知角色编码: " + unknown);
        }
        if (containsAdminRole(roles) && !isSuperAdmin(adminId)) {
            throw new BusinessException(ErrorCode.PERMISSION_DENIED, "只有超级管理员可以创建管理员账号");
        }

        // ---- 阶段1：本地事务落库（用户名撞唯一键的并发竞态由 DB 约束兜底）----
        User u = txTemplate.execute(tx -> {
            User nu = new User();
            nu.setUsername(req.username());
            nu.setPasswordHash(passwordEncoder.encode(req.password()));
            nu.setRealName(req.realName());
            nu.setEmail(req.email());
            nu.setStatus("ACTIVE");
            userMapper.insert(nu);   // 自增 id ≥ 10006

            for (String code : roles) {
                UserRole ur = new UserRole();
                ur.setUserId(nu.getId());
                ur.setRoleId(roleIdByCode.get(code));
                userRoleMapper.insert(ur);
            }

            UserKey uk = new UserKey();
            uk.setUserId(nu.getId());
            uk.setSm9Identity("user:" + TENANT + ":" + nu.getId() + ":" + req.email());
            uk.setKeyStatus("UNINITIALIZED");
            uk.setDeviceBound(false);
            userKeyMapper.insert(uk);
            return nu;
        });
        String identity = "user:" + TENANT + ":" + u.getId() + ":" + req.email();

        // ---- 阶段2：KGC 登记（已提交、不持锁）；失败 → 补偿删除 ----
        try {
            kgcClient.registerIdentity(u.getId(), identity);
        } catch (RuntimeException e) {
            compensateDelete(u.getId());
            auditService.record(adminId, "USER_CREATE_FAIL", "USER", String.valueOf(u.getId()), clientIp, null,
                    "KGC 登记失败已补偿删除：" + req.username() + " 身份=" + identity + " 原因=" + e.getMessage());
            log.warn("admin {} 新增用户 {} KGC 登记失败，已补偿删除本地数据", adminId, req.username());
            throw e;
        }

        auditService.record(adminId, "USER_CREATE", "USER", String.valueOf(u.getId()), clientIp, null,
                "新增用户 " + req.username() + " 角色=" + roles + " 身份=" + identity);
        log.info("admin {} 新增用户 {}({}) 身份 {}", adminId, req.username(), u.getId(), identity);
        return new UserSummary(u.getId(), u.getUsername(), u.getRealName(), u.getEmail(), u.getStatus(),
                roles, "UNINITIALIZED");
    }

    // ---------- 权限分级辅助 ----------

    private boolean isSuperAdmin(Long userId) {
        return roleMapper.selectRoleCodesByUserId(userId).contains(ROLE_SUPER_ADMIN);
    }

    private boolean holdsAdminRole(Long userId) {
        return roleMapper.selectRoleCodesByUserId(userId).stream().anyMatch(ADMIN_ROLES::contains);
    }

    private static boolean containsAdminRole(List<String> roleCodes) {
        return roleCodes.stream().anyMatch(ADMIN_ROLES::contains);
    }

    /** 当前可用管理员数：状态 ACTIVE 且持有管理员类角色的用户数。 */
    private long countActiveAdmins() {
        Set<Long> adminIds = userRoleMapper.selectAllRoleCodes().stream()
                .filter(v -> ADMIN_ROLES.contains(v.getRoleCode()))
                .map(UserRoleCodeView::getUserId)
                .collect(Collectors.toSet());
        if (adminIds.isEmpty()) {
            return 0;
        }
        return userMapper.selectList(new LambdaQueryWrapper<User>()
                .eq(User::getStatus, "ACTIVE")
                .in(User::getId, adminIds)).size();
    }

    /**
     * "最后一个管理员"保底：目标当前是可用管理员且系统只剩这一个时，禁止使其失去管理员可用性
     * （降权走 updateRoles、停用走 updateStatus 两处调用）。显式规则，不再依赖"禁止改自己"的副作用。
     */
    private void assertNotLastActiveAdmin(User target, String action) {
        if ("ACTIVE".equals(target.getStatus()) && holdsAdminRole(target.getId()) && countActiveAdmins() <= 1) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST,
                    "系统必须至少保留一个可用管理员，不能" + action + "最后一个管理员");
        }
    }

    /** Saga 补偿：按外键逆序删除阶段1 落库的三表数据。失败仅记日志（登记幂等，人工可重试清理）。 */
    private void compensateDelete(Long userId) {
        try {
            txTemplate.executeWithoutResult(tx -> {
                userKeyMapper.delete(new LambdaQueryWrapper<UserKey>().eq(UserKey::getUserId, userId));
                userRoleMapper.delete(new LambdaQueryWrapper<UserRole>().eq(UserRole::getUserId, userId));
                userMapper.deleteById(userId);
            });
        } catch (RuntimeException ce) {
            log.error("补偿删除失败 userId={}（KGC 登记幂等，可人工清理后重试）", userId, ce);
        }
    }

    public List<UserSummary> listUsers() {
        List<User> users = userMapper.selectList(null);

        Map<Long, List<String>> rolesByUser = userRoleMapper.selectAllRoleCodes().stream()
                .collect(Collectors.groupingBy(UserRoleCodeView::getUserId,
                        Collectors.mapping(UserRoleCodeView::getRoleCode, Collectors.toList())));

        Map<Long, String> keyStatusByUser = userKeyMapper.selectList(null).stream()
                .collect(Collectors.toMap(UserKey::getUserId, UserKey::getKeyStatus));

        return users.stream()
                .map(u -> new UserSummary(
                        u.getId(), u.getUsername(), u.getRealName(), u.getEmail(), u.getStatus(),
                        rolesByUser.getOrDefault(u.getId(), List.of()),
                        keyStatusByUser.get(u.getId())))
                .toList();
    }

    /** 改用户状态（ACTIVE/DISABLED/LOCKED）。禁止管理员改自己的状态，防自锁。 */
    @Transactional
    public void updateStatus(Long adminId, Long targetUserId, String status, String clientIp) {
        if (status == null || !VALID_STATUS.contains(status)) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "非法状态值，仅允许 ACTIVE/DISABLED/LOCKED");
        }
        if (adminId.equals(targetUserId)) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "不能修改自己的账号状态");
        }
        User u = userMapper.selectById(targetUserId);
        if (u == null) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "用户不存在: " + targetUserId);
        }
        if (!isSuperAdmin(adminId) && holdsAdminRole(targetUserId)) {
            throw new BusinessException(ErrorCode.PERMISSION_DENIED, "只有超级管理员可以修改管理员账号的状态");
        }
        if (!"ACTIVE".equals(status)) {
            assertNotLastActiveAdmin(u, "停用/锁定");
        }
        String old = u.getStatus();
        u.setStatus(status);
        userMapper.updateById(u);
        auditService.record(adminId, "USER_STATUS", "USER", String.valueOf(targetUserId), clientIp, null,
                "状态 " + old + " → " + status);
        log.info("admin {} 改用户 {} 状态 {} → {}", adminId, targetUserId, old, status);
    }

    /** 整集替换用户角色。校验角色编码存在；禁止管理员改自己的角色，防自降权。 */
    @Transactional
    public void updateRoles(Long adminId, Long targetUserId, List<String> roleCodes, String clientIp) {
        if (roleCodes == null || roleCodes.isEmpty()) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "角色不能为空");
        }
        if (adminId.equals(targetUserId)) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "不能修改自己的角色");
        }
        User u = userMapper.selectById(targetUserId);
        if (u == null) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "用户不存在: " + targetUserId);
        }
        Map<String, Long> roleIdByCode = roleMapper.selectList(null).stream()
                .collect(Collectors.toMap(Role::getRoleCode, Role::getId));
        List<String> unknown = roleCodes.stream().distinct().filter(c -> !roleIdByCode.containsKey(c)).toList();
        if (!unknown.isEmpty()) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST, "未知角色编码: " + unknown);
        }
        if (!isSuperAdmin(adminId)) {
            if (holdsAdminRole(targetUserId)) {
                throw new BusinessException(ErrorCode.PERMISSION_DENIED, "只有超级管理员可以修改管理员账号的角色");
            }
            if (containsAdminRole(roleCodes)) {
                throw new BusinessException(ErrorCode.PERMISSION_DENIED, "只有超级管理员可以授予管理员角色");
            }
        }
        if (!containsAdminRole(roleCodes)) {
            assertNotLastActiveAdmin(u, "降级");
        }
        // 重置：删旧 + 插新
        userRoleMapper.delete(new LambdaQueryWrapper<UserRole>().eq(UserRole::getUserId, targetUserId));
        for (String code : roleCodes.stream().distinct().toList()) {
            UserRole ur = new UserRole();
            ur.setUserId(targetUserId);
            ur.setRoleId(roleIdByCode.get(code));
            userRoleMapper.insert(ur);
        }
        auditService.record(adminId, "USER_ROLES", "USER", String.valueOf(targetUserId), clientIp, null,
                "角色重置为 " + roleCodes.stream().distinct().toList());
        log.info("admin {} 改用户 {} 角色 → {}", adminId, targetUserId, roleCodes);
    }
}
