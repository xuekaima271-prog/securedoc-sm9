package com.securedoc.app.service;

import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.entity.LoginAttempt;
import com.securedoc.app.mapper.LoginAttemptMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 登录限流（Step 3.5，对应 §2.2.1 登录失败记录/账号锁定/IP 限流）。
 * 两道防线：
 *   1) 账号维度（持久化到 login_attempts 表）：连续失败 N 次 → 锁定一段时间；登录成功清零。
 *   2) IP 维度（Caffeine 内存，窗口过期，替代 Redis）：单 IP 失败过多 → 限流。
 * DB-2 缓解：仅按用户名锁定会被"狂错他人密码"攻击者用来锁死账号；叠加 IP 维度后，
 *   攻击者在锁掉多个账号前先被 IP 限流挡住。该取舍在论文安全分析中说明。
 */
@Service
public class LoginThrottleService {

    private final LoginAttemptMapper mapper;
    private final SecurityEventService securityEvents;
    private final int maxFailures;
    private final int lockMinutes;
    private final int ipMaxFailures;
    private final Cache<String, AtomicInteger> ipFailures;

    public LoginThrottleService(
            LoginAttemptMapper mapper,
            SecurityEventService securityEvents,
            @Value("${securedoc.login.max-failures:5}") int maxFailures,
            @Value("${securedoc.login.lock-minutes:15}") int lockMinutes,
            @Value("${securedoc.login.ip-max-failures:10}") int ipMaxFailures,
            @Value("${securedoc.login.ip-window-minutes:1}") int ipWindowMinutes) {
        this.mapper = mapper;
        this.securityEvents = securityEvents;
        this.maxFailures = maxFailures;
        this.lockMinutes = lockMinutes;
        this.ipMaxFailures = ipMaxFailures;
        this.ipFailures = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(ipWindowMinutes))
                .maximumSize(100_000)
                .build();
    }

    /** 登录前校验：账号是否锁定 / IP 是否被限流。两者都用 RATE_LIMITED(429)。 */
    public void assertAllowed(String username, String ip) {
        LoginAttempt a = mapper.selectByUsername(username);
        if (a != null && a.getLockedUntil() != null && a.getLockedUntil().isAfter(LocalDateTime.now())) {
            throw new BusinessException(ErrorCode.RATE_LIMITED, "账号已锁定，请稍后再试");
        }
        AtomicInteger c = ipFailures.getIfPresent(ip);
        if (c != null && c.get() >= ipMaxFailures) {
            throw new BusinessException(ErrorCode.RATE_LIMITED, "该来源失败次数过多，请稍后再试");
        }
    }

    /**
     * 记录一次失败：账号失败计数+1（达阈值则锁定），IP 失败计数+1。
     * THROTTLE-1 加固：并发下两请求同时"查无→插入"会撞 unique(username)，
     * 捕获唯一键冲突后重查并退化为 update 路径（计数至少+1，不丢锁定语义）。
     */
    public void recordFailure(String username, String ip) {
        LocalDateTime now = LocalDateTime.now();
        LoginAttempt a = mapper.selectByUsername(username);
        if (a == null) {
            LoginAttempt fresh = new LoginAttempt();
            fresh.setUsername(username);
            fresh.setClientIp(ip);
            fresh.setFailCount(1);
            fresh.setLastFailedAt(now);
            if (1 >= maxFailures) {
                fresh.setLockedUntil(now.plusMinutes(lockMinutes));
                securityEvents.record("BRUTE_FORCE_LOCK", SecurityEventService.HIGH, null, ip, username,
                        "账号连续失败达 " + maxFailures + " 次，已锁定 " + lockMinutes + " 分钟");
            }
            try {
                mapper.insert(fresh);
                bumpIp(ip);
                return;                                     // 插入成功
            } catch (org.springframework.dao.DuplicateKeyException e) {
                a = mapper.selectByUsername(username);      // 并发已建行 → 走 update 追加
                if (a == null) { bumpIp(ip); return; }      // 极端兜底：放弃本次账号计数
            }
        }
        updateFailure(a, username, ip, now);
        bumpIp(ip);
    }

    /** update 路径：锁定过期开新窗口，达阈值设置锁定。 */
    private void updateFailure(LoginAttempt a, String username, String ip, LocalDateTime now) {
        boolean lockExpired = a.getLockedUntil() != null && a.getLockedUntil().isBefore(now);
        int fc = lockExpired ? 1 : (a.getFailCount() == null ? 1 : a.getFailCount() + 1);
        LocalDateTime lockedUntil = fc >= maxFailures ? now.plusMinutes(lockMinutes) : null;
        if (lockedUntil != null && fc == maxFailures) {   // 仅在首次达到阈值时记一次事件（§2.2.12 多次登录失败）
            securityEvents.record("BRUTE_FORCE_LOCK", SecurityEventService.HIGH, null, ip, username,
                    "账号连续失败达 " + maxFailures + " 次，已锁定 " + lockMinutes + " 分钟");
        }
        // 用 UpdateWrapper 显式写入（含把 locked_until 置 null 的情形；updateById 会忽略 null）
        mapper.update(null, new UpdateWrapper<LoginAttempt>()
                .eq("username", username)
                .set("fail_count", fc)
                .set("client_ip", ip)
                .set("last_failed_at", now)
                .set("locked_until", lockedUntil)
                .set("updated_at", now));
    }

    private void bumpIp(String ip) {
        int n = ipFailures.asMap().computeIfAbsent(ip, k -> new AtomicInteger()).incrementAndGet();
        if (n == ipMaxFailures) {   // 恰好越过阈值记一次（窗口过期后可再次触发）
            securityEvents.record("IP_THROTTLED", SecurityEventService.MEDIUM, null, ip, ip,
                    "单 IP 窗口内登录失败达 " + ipMaxFailures + " 次，已限流");
        }
    }

    /** 登录成功：清零该账号失败计数与锁定。 */
    public void recordSuccess(String username) {
        LoginAttempt a = mapper.selectByUsername(username);
        if (a != null) {
            mapper.update(null, new UpdateWrapper<LoginAttempt>()
                    .eq("username", username)
                    .set("fail_count", 0)
                    .set("locked_until", null)
                    .set("updated_at", LocalDateTime.now()));
        }
    }

    /** 仅供测试：清空账号失败记录与 IP 计数。 */
    public void clearAll() {
        mapper.delete(null);
        ipFailures.invalidateAll();
    }
}
