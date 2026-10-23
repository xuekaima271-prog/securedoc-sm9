package com.securedoc.app.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedoc.app.common.ApiResponse;
import com.securedoc.app.common.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/** 未认证访问受保护资源时返回统一 JSON（401 AUTH_REQUIRED），而非 Spring 默认登录页。 */
@Component
public class RestAuthEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    public RestAuthEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.setStatus(ErrorCode.AUTH_REQUIRED.httpStatus);
        response.setContentType("application/json;charset=UTF-8");
        objectMapper.writeValue(response.getWriter(),
                ApiResponse.error(ErrorCode.AUTH_REQUIRED.name(), ErrorCode.AUTH_REQUIRED.defaultMessage));
    }
}
