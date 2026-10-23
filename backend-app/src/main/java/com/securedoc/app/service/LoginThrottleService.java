package com.securedoc.app.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
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
 *   1) 组合维度（持久化到 login_attempts 表）：同一 (账号, 来源IP) 连续失败 N 次 → 锁定该组合一段时间。
 *   2) IP 维度（Caffeine 内存，窗口过期，替代 Redis）：单 IP 失败过多 → 限流（不分账号）。
 *
 * M-5 改造（2026-10-23）：原实现是账号全局锁定——攻击者从任意 IP 连错 5 次即可把任意账号
 *   （含 admin）对所有人锁死 15 分钟，多 IP 轮换可无限续锁，形成对管理功能的拒绝服务。
 *   现改为 (账号, IP) 组合锁定：攻击者只能锁住「目标账号 × 自己来源」这一组合，
 *   账号持有人从自己的常用来源登录不受影响，"锁死管理员"不再成立。
 * 取舍（如实记录）：组合维度下，分布式多 IP 对同一账号的低速猜解不再触发账号级硬锁，
 *   仅剩单 IP 维度兜底（同 IP 跨账号 10 次/分钟）+ 口令强度 + LOGIN_FAIL 审计/安全事件监测。
 *   这是"防暴力破解"与"防锁定 DoS"之间的经典权衡，本系统优先消除可锁死管理员的可用性风险；
 *   若后续接入验证码/渐进延迟，可在 assertAllowed 处按组合失败数叠加，不必再改维度。
 * 附带修复：失败计数改走原子自增 SQL（incrementFailure 的 CASE 表达式），
 *   消除原先「先查后写绝对值」在并发失败下互相覆盖、少计的竞态（残余风险登记项）。
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

    /** 登录前校验：该 (账号, IP) 组合是否锁定 / 该 IP 是否被全局限流。两者都用 RATE_LIMITED(429)。 */
    public void assertAllowed(String username, String ip) {
        LoginAttempt a = mapper.selectByUsernameAndIp(username, ip);
        if (a != null && a.getLockedUntil() != null && a.getLockedUntil().isAfter(LocalDateTime.now())) {
            throw new BusinessException(ErrorCode.RATE_LIMITED, "该账号从当前来源失败次数过多，请稍后再试");
        }
        AtomicInteger c = ipFailures.getIfPresent(ip);
        if (c != null && c.get() >= ipMaxFailures) {
            throw new BusinessException(ErrorCode.RATE_LIMITED, "该来源失败次数过多，请稍后再试");
        }
    }

    /**
     * 记录一次失败：组合计数原子自增，达阈值落锁；IP 失败计数+1。
     * 组合行不存在时先插入（fail_count=1）；与并发插入撞唯一键时退化为自增路径。
     */
    public void recordFailure(String username, String ip) {
        LocalDateTime now = LocalDateTime.now();
        if (mapper.incrementFailure(username, ip, now) == 0) {
            LoginAttempt fresh = new LoginAttempt();
            fresh.setUsername(username);
            fresh.setClientIp(ip);
            fresh.setFailCount(1);
            fresh.setLastFailedAt(now);
            try {
                mapper.insert(fresh);
            } catch (org.springframework.dao.DuplicateKeyException e) {
                mapper.incrementFailure(username, ip, now);   // 并发已建行 → 补一次自增，不丢计数
            }
        }
        int locked = mapper.lockIfThresholdReached(username, ip, now.plusMinutes(lockMinutes), maxFailures, now);
        if (locked == 1) {   // 条件更新保证只有真正落锁的调用者记事件，并发下不重复
            securityEvents.record("BRUTE_FORCE_LOCK", SecurityEventService.HIGH, null, ip, username,
                    "账号从同一来源连续失败达 " + maxFailures + " 次，已锁定该来源 " + lockMinutes + " 分钟");
        }
        bumpIp(ip);
    }

    private void bumpIp(String ip) {
        int n = ipFailures.asMap().computeIfAbsent(ip, k -> new AtomicInteger()).incrementAndGet();
        if (n == ipMaxFailures) {   // 恰好越过阈值记一次（窗口过期后可再次触发）
            securityEvents.record("IP_THROTTLED", SecurityEventService.MEDIUM, null, ip, ip,
                    "单 IP 窗口内登录失败达 " + ipMaxFailures + " 次，已限流");
        }
    }

    /** 登录成功：清零该 (账号, 本次来源) 组合的失败计数与锁定；其他来源的失败记录不牵连。 */
    public void recordSuccess(String username, String ip) {
        mapper.delete(new LambdaQueryWrapper<LoginAttempt>()
                .eq(LoginAttempt::getUsername, username)
                .eq(LoginAttempt::getClientIp, ip));
    }

    /** 仅供测试：清空全部组合失败记录与 IP 计数。 */
    public void clearAll() {
        mapper.delete(null);
        ipFailures.invalidateAll();
    }
}
