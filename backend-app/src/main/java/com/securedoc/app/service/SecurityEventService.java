package com.securedoc.app.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.securedoc.app.common.PageResult;
import com.securedoc.app.entity.SecurityEvent;
import com.securedoc.app.mapper.SecurityEventMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 安全事件服务（§2.2.12）。
 * record 为 best-effort：安全事件记录失败绝不能中断主业务流（只记日志）；
 * 事件本身即告警凭据，与审计哈希链（行为流水）互补——事件面向"攻击面"，审计面向"操作面"。
 */
@Service
public class SecurityEventService {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventService.class);

    /** 事件级别 */
    public static final String HIGH = "HIGH";
    public static final String MEDIUM = "MEDIUM";
    public static final String LOW = "LOW";

    private final SecurityEventMapper mapper;

    public SecurityEventService(SecurityEventMapper mapper) {
        this.mapper = mapper;
    }

    /** 记录安全事件（best-effort，绝不抛出）。 */
    public void record(String eventType, String severity, Long actorId,
                       String clientIp, String resource, String detail) {
        try {
            SecurityEvent e = new SecurityEvent();
            e.setEventType(eventType);
            e.setSeverity(severity);
            e.setActorId(actorId);
            e.setClientIp(clientIp);
            e.setResource(resource == null ? null : truncate(resource, 255));
            e.setDetail(detail == null ? null : truncate(detail, 1000));
            mapper.insert(e);
            log.warn("安全事件[{}/{}] actor={} ip={} resource={} {}", eventType, severity, actorId, clientIp, resource, detail);
        } catch (RuntimeException ex) {
            log.error("安全事件记录失败（不影响主流程） type={}", eventType, ex);
        }
    }

    /** 分页查询（手动分页，同 AuditService 约定：selectCount + LIMIT）。 */
    public PageResult<SecurityEvent> query(long page, long size, String eventType, String severity) {
        long p = Math.max(1, page);
        long s = Math.min(Math.max(1, size), 200);

        LambdaQueryWrapper<SecurityEvent> w = new LambdaQueryWrapper<>();
        if (eventType != null && !eventType.isBlank()) w.eq(SecurityEvent::getEventType, eventType.trim());
        if (severity != null && !severity.isBlank()) w.eq(SecurityEvent::getSeverity, severity.trim());

        long total = mapper.selectCount(w);
        w.orderByDesc(SecurityEvent::getId);
        w.last("LIMIT " + (p - 1) * s + ", " + s);
        List<SecurityEvent> records = total == 0 ? List.of() : mapper.selectList(w);
        return new PageResult<>(total, p, s, records);
    }

    private static String truncate(String v, int max) {
        return v.length() <= max ? v : v.substring(0, max);
    }
}
