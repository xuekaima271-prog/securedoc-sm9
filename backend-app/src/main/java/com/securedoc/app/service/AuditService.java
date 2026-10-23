package com.securedoc.app.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.securedoc.app.common.AuditChainResult;
import com.securedoc.app.common.PageResult;
import com.securedoc.app.crypto.Sm3;
import com.securedoc.app.entity.AuditLog;
import com.securedoc.app.mapper.AuditLogMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * 审计日志服务。写入为 best-effort：审计失败只记 error，绝不影响主业务流程。
 *
 * Step8：SM3 哈希链防篡改（§2.2.11 / §13）。每条 currentHash = SM3(previousHash | 规范化内容)，
 * 创世 previousHash="GENESIS"。任何对历史记录的篡改都会使该条及其后所有 currentHash 校验失败。
 * 用 LOCK 串行化「读链尾→算→插」，避免单实例内并发分叉（多实例/嵌套事务下的残余风险见账本 AUDIT-1）。
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);
    private static final String GENESIS = "GENESIS";

    private final AuditLogMapper mapper;
    private final SecurityEventService securityEvents;
    private final Object chainLock = new Object();

    public AuditService(AuditLogMapper mapper, SecurityEventService securityEvents) {
        this.mapper = mapper;
        this.securityEvents = securityEvents;
    }

    /** 记录一条审计（best-effort，带 SM3 哈希链）。 */
    public void record(Long actorId, String action, String resourceType, String resourceId,
                       String clientIp, String userAgent, String detail) {
        try {
            AuditLog a = new AuditLog();
            a.setActorId(actorId);
            a.setAction(action);
            a.setResourceType(resourceType);
            a.setResourceId(resourceId);
            a.setClientIp(clientIp);
            a.setUserAgent(truncate(userAgent, 255));
            a.setDetail(detail);
            // 秒级时间戳：显式设置使其参与哈希且与 DB 存值一致（避免纳秒精度回读不匹配）
            a.setCreatedAt(LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS));
            synchronized (chainLock) {
                String prev = mapper.selectLastHash();
                if (prev == null || prev.isBlank()) prev = GENESIS;
                a.setPreviousHash(prev);
                a.setCurrentHash(computeHash(prev, a));
                mapper.insert(a);
            }
        } catch (Exception e) {
            log.error("写审计日志失败 action={}, actorId={}", action, actorId, e);
        }
    }

    /** 规范化内容（字段顺序固定、null→空串），用于哈希与校验，二者必须一致。 */
    private static String canonicalContent(AuditLog a) {
        return String.join("|",
                n(a.getActorId()), n(a.getAction()), n(a.getResourceType()), n(a.getResourceId()),
                n(a.getClientIp()), n(a.getDetail()),
                a.getCreatedAt() == null ? "" : a.getCreatedAt().truncatedTo(ChronoUnit.SECONDS).toString());
    }

    private static String computeHash(String previousHash, AuditLog a) {
        String material = previousHash + "|" + canonicalContent(a);
        return Sm3.digestBase64(material.getBytes(StandardCharsets.UTF_8));
    }

    private static String n(Object o) { return o == null ? "" : o.toString(); }

    /**
     * 校验整条哈希链：按 id 升序逐条重算 currentHash 与存值比对，并核对 previousHash 链接。
     * 返回首个断裂记录 id（若有）。
     */
    public AuditChainResult verifyChain() {
        List<AuditLog> all = mapper.selectList(new LambdaQueryWrapper<AuditLog>().orderByAsc(AuditLog::getId));
        String prev = GENESIS;
        long n = 0;
        for (AuditLog a : all) {
            n++;
            if (!prev.equals(a.getPreviousHash() == null ? GENESIS : a.getPreviousHash())) {
                securityEvents.record("AUDIT_CHAIN_BROKEN", SecurityEventService.HIGH, null, null,
                        "audit_logs#" + a.getId(), "审计哈希链断裂：previousHash 不衔接（记录被删除/重排/篡改）");
                return new AuditChainResult(false, all.size(), a.getId(),
                        "第 " + a.getId() + " 条 previousHash 与上一条 currentHash 不衔接（记录被删除/重排/篡改）");
            }
            String recomputed = computeHash(prev, a);
            if (!recomputed.equals(a.getCurrentHash())) {
                securityEvents.record("AUDIT_CHAIN_BROKEN", SecurityEventService.HIGH, null, null,
                        "audit_logs#" + a.getId(), "审计哈希链断裂：currentHash 重算不一致（内容被篡改）");
                return new AuditChainResult(false, all.size(), a.getId(),
                        "第 " + a.getId() + " 条内容被篡改（currentHash 重算不一致）");
            }
            prev = a.getCurrentHash();
        }
        return new AuditChainResult(true, all.size(), null, "审计哈希链完整，共 " + n + " 条记录自洽");
    }

    /**
     * 分页查询审计日志（按时间倒序），可选按 action / 时间范围过滤。
     * 手动分页（selectCount + LIMIT），不依赖 jsqlparser 分页插件；page/size 为数值，LIMIT 拼接无注入风险。
     */
    public PageResult<AuditLog> query(long page, long size, String action, String from, String to) {
        long safePage = page < 1 ? 1 : page;
        long safeSize = (size < 1 || size > 200) ? 20 : size;   // 限制每页上限，防一次拉太多

        LambdaQueryWrapper<AuditLog> w = new LambdaQueryWrapper<>();
        if (action != null && !action.isBlank()) {
            w.eq(AuditLog::getAction, action);
        }
        LocalDateTime fromTs = parseOrNull(from);
        LocalDateTime toTs = parseOrNull(to);
        if (fromTs != null) w.ge(AuditLog::getCreatedAt, fromTs);
        if (toTs != null) w.le(AuditLog::getCreatedAt, toTs);

        long total = mapper.selectCount(w);   // 先 count（此时 wrapper 不含 orderBy/limit）

        w.orderByDesc(AuditLog::getCreatedAt);
        w.last("LIMIT " + ((safePage - 1) * safeSize) + ", " + safeSize);
        java.util.List<AuditLog> records = total == 0 ? java.util.List.of() : mapper.selectList(w);

        return new PageResult<>(total, safePage, safeSize, records);
    }

    private LocalDateTime parseOrNull(String s) {
        if (s == null || s.isBlank()) return null;
        try {
            return LocalDateTime.parse(s);   // ISO_LOCAL_DATE_TIME，如 2026-06-22T10:00:00
        } catch (DateTimeParseException e) {
            return null;                     // 非法时间过滤忽略，不报错
        }
    }

    private String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max);
    }
}
