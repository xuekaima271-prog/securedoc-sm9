package com.securedoc.kgc.web;

import com.securedoc.kgc.common.ApiResponse;
import com.securedoc.kgc.common.BusinessException;
import com.securedoc.kgc.common.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** 全局异常处理：把异常统一转成 ApiResponse + 对应 HTTP 状态。 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

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

    /** 请求体畸形/无法解析的 JSON → 400，而非落到 500 */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> handleUnreadable(HttpMessageNotReadableException e) {
        return ResponseEntity.status(ErrorCode.INVALID_REQUEST.httpStatus)
                .body(ApiResponse.error(ErrorCode.INVALID_REQUEST.name(), "请求体格式错误"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleOther(Exception e) {
        log.error("未处理异常", e);   // 仅记日志，不向客户端泄露内部细节
        return ResponseEntity.status(ErrorCode.INTERNAL_ERROR.httpStatus)
                .body(ApiResponse.error(ErrorCode.INTERNAL_ERROR.name(), ErrorCode.INTERNAL_ERROR.defaultMessage));
    }
}
