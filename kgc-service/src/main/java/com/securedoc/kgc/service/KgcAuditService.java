package com.securedoc.kgc.service;

import com.securedoc.kgc.entity.AuditLog;
import com.securedoc.kgc.mapper.AuditLogMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/** KGC 审计写入（best-effort）：审计失败只记 error，绝不影响签发主流程。 */
@Service
public class KgcAuditService {

    private static final Logger log = LoggerFactory.getLogger(KgcAuditService.class);

    private final AuditLogMapper mapper;

    public KgcAuditService(AuditLogMapper mapper) {
        this.mapper = mapper;
    }

    public void record(Long actorId, String action, String resourceId, String clientIp, String detail) {
        try {
            AuditLog a = new AuditLog();
            a.setActorId(actorId);
            a.setAction(action);
            a.setResourceType("KGC");
            a.setResourceId(resourceId);
            a.setClientIp(clientIp);
            a.setDetail(detail);
            mapper.insert(a);
        } catch (Exception e) {
            log.error("写 KGC 审计日志失败 action={}, actorId={}", action, actorId, e);
        }
    }
}
