package com.securedoc.kgc.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedoc.kgc.common.ApiResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UrlPathHelper;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * KGC 服务令牌过滤器（MVP 鉴权，§2.6 安全边界的工程落地）。
 *
 * 所有 SM9 接口要求请求头 X-KGC-Token 与配置 kgc.service-token 一致（常量时间比较）。
 * 仅健康检查公开；主公钥和身份标识也只能经应用服务器代理读取。
 * 生产环境应升级为 KGC_ADMIN 独立权限 + mTLS（论文中说明），此处为可运行的最小可信边界。
 */
@Component
public class KgcTokenFilter extends OncePerRequestFilter {

    private static final String SM9_API_ROOT = "/kgc/sm9";
    private static final UrlPathHelper PATH_HELPER = new UrlPathHelper();

    static {
        // Normalize matrix parameters, URL escapes, and dot segments before evaluating the API boundary.
        PATH_HELPER.setRemoveSemicolonContent(true);
        PATH_HELPER.setUrlDecode(true);
    }

    private final String token;
    private final ObjectMapper om = new ObjectMapper();

    public KgcTokenFilter(@Value("${kgc.service-token:}") String token) {
        this.token = token;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        if (requiresToken(req)) {
            if (!tokenValid(req.getHeader("X-KGC-Token"))) {
                res.setStatus(401);
                res.setContentType("application/json;charset=UTF-8");
                res.getWriter().write(om.writeValueAsString(
                        ApiResponse.error("KGC_UNAUTHORIZED", "KGC 服务令牌缺失或无效")));
                return;
            }
        }
        chain.doFilter(req, res);
    }

    private static boolean requiresToken(HttpServletRequest request) {
        String path = StringUtils.cleanPath(PATH_HELPER.getPathWithinApplication(request));
        return SM9_API_ROOT.equals(path) || path.startsWith(SM9_API_ROOT + "/");
    }

    private boolean tokenValid(String provided) {
        if (token == null || token.isBlank() || provided == null) return false;
        // 常量时间比较，避免计时侧信道
        return MessageDigest.isEqual(
                token.getBytes(StandardCharsets.UTF_8),
                provided.getBytes(StandardCharsets.UTF_8));
    }
}
