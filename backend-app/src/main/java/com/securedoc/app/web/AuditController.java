package com.securedoc.app.web;

import com.securedoc.app.common.ApiResponse;
import com.securedoc.app.common.AuditChainResult;
import com.securedoc.app.common.PageResult;
import com.securedoc.app.entity.AuditLog;
import com.securedoc.app.entity.SecurityEvent;
import com.securedoc.app.service.AuditService;
import com.securedoc.app.service.SecurityEventService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 审计查询接口（§2.10）。面向安全审计员/系统管理员。 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditService auditService;
    private final SecurityEventService securityEventService;

    public AuditController(AuditService auditService, SecurityEventService securityEventService) {
        this.auditService = auditService;
        this.securityEventService = securityEventService;
    }

    @GetMapping("/logs")
    @PreAuthorize("hasAnyRole('SECURITY_AUDITOR','SYS_ADMIN','SUPER_ADMIN')")
    public ApiResponse<PageResult<AuditLog>> logs(
            @RequestParam(defaultValue = "1") long page,
            @RequestParam(defaultValue = "20") long size,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to) {
        return ApiResponse.ok(auditService.query(page, size, action, from, to));
    }

    /** 校验审计哈希链完整性（§2.2.11 / §13）：证明日志未被篡改/删除/重排。 */
    @GetMapping("/verify")
    @PreAuthorize("hasAnyRole('SECURITY_AUDITOR','SYS_ADMIN','SUPER_ADMIN')")
    public ApiResponse<AuditChainResult> verify() {
        return ApiResponse.ok(auditService.verifyChain());
    }

    /** 安全事件查询（§2.2.12 安全事件告警，增强项）。 */
    @GetMapping("/security-events")
    @PreAuthorize("hasAnyRole('SECURITY_AUDITOR','SYS_ADMIN','SUPER_ADMIN')")
    public ApiResponse<PageResult<SecurityEvent>> securityEvents(
            @RequestParam(defaultValue = "1") long page,
            @RequestParam(defaultValue = "20") long size,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String severity) {
        return ApiResponse.ok(securityEventService.query(page, size, eventType, severity));
    }
}
