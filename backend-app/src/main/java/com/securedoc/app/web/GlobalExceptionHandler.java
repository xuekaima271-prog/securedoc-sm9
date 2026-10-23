package com.securedoc.app.web;

import com.securedoc.app.common.ApiResponse;
import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ClientIpResolver;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.security.SecurityUser;
import com.securedoc.app.service.SecurityEventService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** 全局异常处理（BE-1）：把异常统一转成 ApiResponse + 对应 HTTP 状态。 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final SecurityEventService securityEvents;
    private final ClientIpResolver clientIpResolver;

    public GlobalExceptionHandler(SecurityEventService securityEvents, ClientIpResolver clientIpResolver) {
        this.securityEvents = securityEvents;
        this.clientIpResolver = clientIpResolver;
    }

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse<Void>> handleBusiness(BusinessException e) {
        ErrorCode c = e.getErrorCode();
        return ResponseEntity.status(c.httpStatus).body(ApiResponse.error(c.name(), e.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidation(MethodArgumentNotValidException e) {
        String msg = e.getBindingResult().getFieldError() != null
                ? e.getBindingResult().getFieldError().getDefaultMessage()
                : ErrorCode.INVALID_REQUEST.defaultMessage;
        return ResponseEntity.status(ErrorCode.INVALID_REQUEST.httpStatus)
                .body(ApiResponse.error(ErrorCode.INVALID_REQUEST.name(), msg));
    }

    /** BE-6：请求体畸形/无法解析的 JSON → 400，而非落到 500 */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> handleUnreadable(HttpMessageNotReadableException e) {
        return ResponseEntity.status(ErrorCode.INVALID_REQUEST.httpStatus)
                .body(ApiResponse.error(ErrorCode.INVALID_REQUEST.name(), "请求体格式错误"));
    }

    /**
     * 方法级鉴权(@PreAuthorize, 3.4) 抛出的拒绝；过滤器级由 RestAccessDeniedHandler 处理。
     * Step15：403 即越权尝试 → 记安全事件 ACCESS_DENIED（§2.2.12）。
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccessDenied(AccessDeniedException e, HttpServletRequest request) {
        Long actorId = null;
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof SecurityUser su) {
            actorId = su.getUserId();
        }
        securityEvents.record("ACCESS_DENIED", SecurityEventService.MEDIUM, actorId,
                clientIpResolver.resolve(request), request.getMethod() + " " + request.getRequestURI(),
                "越权访问被拒（RBAC 403）");
        return ResponseEntity.status(ErrorCode.PERMISSION_DENIED.httpStatus)
                .body(ApiResponse.error(ErrorCode.PERMISSION_DENIED.name(), ErrorCode.PERMISSION_DENIED.defaultMessage));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleOther(Exception e) {
        log.error("未处理异常", e);   // 仅记日志，不向客户端泄露内部细节
        return ResponseEntity.status(ErrorCode.INTERNAL_ERROR.httpStatus)
                .body(ApiResponse.error(ErrorCode.INTERNAL_ERROR.name(), ErrorCode.INTERNAL_ERROR.defaultMessage));
    }
}
