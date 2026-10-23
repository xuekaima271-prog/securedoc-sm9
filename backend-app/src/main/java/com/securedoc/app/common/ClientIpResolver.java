package com.securedoc.app.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 客户端真实 IP 解析（SEC-8）。限流、审计、安全事件记录的来源 IP 统一走这里，不再各自 getRemoteAddr()。
 *
 * <p>默认（app.trust-proxy-headers=false）只信 TCP 直连地址 {@code getRemoteAddr()}，忽略一切代理头；
 * 仅当应用确实部署在可信反向代理之后并显式开启该配置时，才采信 X-Forwarded-For 的第一个 IP
 * （其次 X-Real-IP）。注意：开启时必须保证应用端口只能被该代理访问，否则任何人都能伪造
 * X-Forwarded-For 绕过 IP 限流、污染审计记录里的来源 IP。
 */
@Component
public class ClientIpResolver {

    private final boolean trustProxyHeaders;

    public ClientIpResolver(@Value("${app.trust-proxy-headers:false}") boolean trustProxyHeaders) {
        this.trustProxyHeaders = trustProxyHeaders;
    }

    /** 解析当前请求的客户端 IP，口径见类注释。 */
    public String resolve(HttpServletRequest request) {
        if (trustProxyHeaders) {
            String xff = request.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                String first = xff.split(",")[0].trim();
                if (!first.isEmpty()) {
                    return first;
                }
            }
            String realIp = request.getHeader("X-Real-IP");
            if (realIp != null && !realIp.isBlank()) {
                return realIp.trim();
            }
        }
        return request.getRemoteAddr();
    }

    /** 是否已开启信任代理头（测试/诊断用）。 */
    public boolean isTrustProxyHeaders() {
        return trustProxyHeaders;
    }
}
