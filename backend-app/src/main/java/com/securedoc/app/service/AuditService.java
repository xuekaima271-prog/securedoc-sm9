package com.securedoc.app.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.securedoc.app.common.AuditChainResult;
import com.securedoc.app.common.PageResult;
import com.securedoc.app.crypto.Sm3;
import com.securedoc.app.entity.AuditLog;
import com.securedoc.app.mapper.AuditLogMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * 审计日志服务。写入为 best-effort：审计失败只记 error，绝不影响主业务流程。
 *
 * Step8：SM3 哈希链防篡改（§2.2.11 / §13），创世 previousHash="GENESIS"。
 * M-3 加固（2026-10-23）：原链为无钥 SM3——有 DB 写权限者改任意历史记录后可整链重算、校验照样通过。
 * 现新记录（v2）一律 HMAC-SM3：currentHash = "v2$" + Base64( HMAC-SM3(服务端密钥, previousHash | 规范化内容) )，
 * 密钥仅服务端持有（app.audit.hmac-key，prod 经环境变量注入、无默认值），无钥者无法伪造自洽链。
 * 存量兼容策略（简单可辩护的一种）：v1 旧式哈希无法追溯补签（当时无密钥），只能按原公式校验其自洽；
 * 为防攻击者把整条链"降级重写"为 v1 冒充存量，校验强制两条边界——
 *   ① 版本单调：出现 v2 记录后不允许再出现 v1 记录；
 *   ② 升级边界：v1 记录的 id 必须 <= app.audit.legacy-max-id（升级时由运维一次性设定为
 *      最后一条存量记录的 id；全新部署默认 0，即不接受任何 v1 记录）。
 * 残余（如实记录）：删除链尾记录仍不可检出——那需要把链头/总数定期导出到外部介质做锚点，不在本批范围。
 * 用 LOCK 串行化「读链尾→算→插」，避免单实例内并发分叉（多实例/嵌套事务下的残余风险见账本 AUDIT-1）。
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);
    private static final String GENESIS = "GENESIS";
    /** v2（HMAC）记录的 currentHash 前缀；无前缀即 v1 存量旧式哈希。 */
    private static final String V2_PREFIX = "v2$";

    private final AuditLogMapper mapper;
    private final SecurityEventService securityEvents;
    private final byte[] hmacKey;
    private final long legacyMaxId;
    private final Object chainLock = new Object();

    public AuditService(AuditLogMapper mapper, SecurityEventService securityEvents,
                        @Value("${app.audit.hmac-key:}") String hmacKey,
                        @Value("${app.audit.legacy-max-id:0}") long legacyMaxId) {
        if (hmacKey == null || hmacKey.isBlank()) {
            // fail-closed：密钥缺失时宁可拒绝启动，也不用空钥/弱默认签出"看似有钥"的链
            throw new IllegalStateException(
                    "app.audit.hmac-key 未配置：审计链 HMAC 密钥缺失，拒绝启动（prod 须经 AUDIT_HMAC_KEY 环境变量注入）");
        }
        this.mapper = mapper;
        this.securityEvents = securityEvents;
        this.hmacKey = hmacKey.getBytes(StandardCharsets.UTF_8);
        this.legacyMaxId = legacyMaxId;
    }

    /** 记录一条审计（best-effort，带 HMAC-SM3 哈希链 v2）。 */
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

    /** v2（现行）：HMAC-SM3 带版本前缀。previousHash 为上一条的原始存储值（含其前缀），逐字衔接。 */
    private String computeHash(String previousHash, AuditLog a) {
        String material = previousHash + "|" + canonicalContent(a);
        return V2_PREFIX + Sm3.hmacBase64(hmacKey, material.getBytes(StandardCharsets.UTF_8));
    }

    /** v1（存量）：无钥 SM3，仅供校验升级前写入的老记录，新写入永不使用。 */
    private static String legacyHash(String previousHash, AuditLog a) {
        String material = previousHash + "|" + canonicalContent(a);
        return Sm3.digestBase64(material.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean isV2(String storedHash) {
        return storedHash != null && storedHash.startsWith(V2_PREFIX);
    }

    private static String n(Object o) { return o == null ? "" : o.toString(); }

    /**
     * 校验整条哈希链：按 id 升序逐条按其版本（v1 旧式 / v2 HMAC）重算 currentHash 与存值比对，
     * 并核对 previousHash 衔接与 M-3 的版本边界（单调 + legacy-max-id）。返回首个断裂记录 id（若有）。
     */
    public AuditChainResult verifyChain() {
        List<AuditLog> all = mapper.selectList(new LambdaQueryWrapper<AuditLog>().orderByAsc(AuditLog::getId));
        String prev = GENESIS;
        boolean seenV2 = false;
        long n = 0;
        for (AuditLog a : all) {
            n++;
            if (!prev.equals(a.getPreviousHash() == null ? GENESIS : a.getPreviousHash())) {
                return broken(all.size(), a.getId(),
                        "第 " + a.getId() + " 条 previousHash 与上一条 currentHash 不衔接（记录被删除/重排/篡改）");
            }
            boolean v2 = isV2(a.getCurrentHash());
            if (!v2 && seenV2) {
                return broken(all.size(), a.getId(),
                        "第 " + a.getId() + " 条为旧式无钥哈希，但其前面已出现 HMAC(v2) 记录（版本回退，疑似整链降级重写）");
            }
            if (!v2 && a.getId() != null && a.getId() > legacyMaxId) {
                return broken(all.size(), a.getId(),
                        "第 " + a.getId() + " 条为旧式无钥哈希，且超出存量兼容边界 legacy-max-id=" + legacyMaxId
                                + "（升级后不应再出现 v1 记录）");
            }
            String recomputed = v2 ? computeHash(prev, a) : legacyHash(prev, a);
            if (!recomputed.equals(a.getCurrentHash())) {
                return broken(all.size(), a.getId(),
                        "第 " + a.getId() + " 条内容被篡改（currentHash 重算不一致）");
            }
            seenV2 = seenV2 || v2;
            prev = a.getCurrentHash();
        }
        return new AuditChainResult(true, all.size(), null, "审计哈希链完整，共 " + n + " 条记录自洽");
    }

    private AuditChainResult broken(long total, Long id, String message) {
        securityEvents.record("AUDIT_CHAIN_BROKEN", SecurityEventService.HIGH, null, null,
                "audit_logs#" + id, "审计哈希链断裂：" + message);
        return new AuditChainResult(false, total, id, message);
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
