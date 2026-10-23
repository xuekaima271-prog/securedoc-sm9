package com.securedoc.app.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedoc.app.common.ApiResponse;
import com.securedoc.app.common.ClientIpResolver;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.service.SecurityEventService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 已认证但权限不足时返回统一 JSON（403 PERMISSION_DENIED）。RBAC(3.4) 用。
 * Step15：403 即越权尝试 → 记安全事件 ACCESS_DENIED（§2.2.12），审计员可查。
 */
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;
    private final SecurityEventService securityEvents;
    private final ClientIpResolver clientIpResolver;

    public RestAccessDeniedHandler(ObjectMapper objectMapper, SecurityEventService securityEvents,
                                   ClientIpResolver clientIpResolver) {
        this.objectMapper = objectMapper;
        this.securityEvents = securityEvents;
        this.clientIpResolver = clientIpResolver;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        Long actorId = null;
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof SecurityUser su) {
            actorId = su.getUserId();
        }
        securityEvents.record("ACCESS_DENIED", SecurityEventService.MEDIUM, actorId,
                clientIpResolver.resolve(request), request.getMethod() + " " + request.getRequestURI(),
                "越权访问被拒（RBAC 403）");
        response.setStatus(ErrorCode.PERMISSION_DENIED.httpStatus);
        response.setContentType("application/json;charset=UTF-8");
        objectMapper.writeValue(response.getWriter(),
                ApiResponse.error(ErrorCode.PERMISSION_DENIED.name(), ErrorCode.PERMISSION_DENIED.defaultMessage));
    }
}
