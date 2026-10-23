package com.securedoc.app;

import com.securedoc.app.common.ClientIpResolver;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SEC-8 客户端 IP 解析单测：默认不信任代理头；开启后取 X-Forwarded-For 第一个 IP，
 * 其次 X-Real-IP，再回退直连地址。纯单元测试，不起 Spring 上下文。
 */
class ClientIpResolverTest {

    private static final String REMOTE = "10.0.0.9";

    private MockHttpServletRequest request(String xff, String realIp) {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr(REMOTE);
        if (xff != null) {
            req.addHeader("X-Forwarded-For", xff);
        }
        if (realIp != null) {
            req.addHeader("X-Real-IP", realIp);
        }
        return req;
    }

    @Test
    void 未开启信任时忽略代理头_只用直连地址() {
        ClientIpResolver resolver = new ClientIpResolver(false);
        assertThat(resolver.isTrustProxyHeaders()).isFalse();
        assertThat(resolver.resolve(request("203.0.113.7, 172.16.0.1", "203.0.113.8")))
                .isEqualTo(REMOTE);
    }

    @Test
    void 开启后取XForwardedFor第一个IP() {
        ClientIpResolver resolver = new ClientIpResolver(true);
        assertThat(resolver.resolve(request("203.0.113.7, 172.16.0.1", null)))
                .isEqualTo("203.0.113.7");
    }

    @Test
    void 开启后XFF单个值带空格会trim() {
        ClientIpResolver resolver = new ClientIpResolver(true);
        assertThat(resolver.resolve(request("  203.0.113.7  ", null)))
                .isEqualTo("203.0.113.7");
    }

    @Test
    void 开启后无XFF时用XRealIP() {
        ClientIpResolver resolver = new ClientIpResolver(true);
        assertThat(resolver.resolve(request(null, "203.0.113.8")))
                .isEqualTo("203.0.113.8");
    }

    @Test
    void 开启后XFF为空白时跳过用XRealIP() {
        ClientIpResolver resolver = new ClientIpResolver(true);
        assertThat(resolver.resolve(request("   ", "203.0.113.8")))
                .isEqualTo("203.0.113.8");
    }

    @Test
    void 开启后代理头都缺失时回退直连地址() {
        ClientIpResolver resolver = new ClientIpResolver(true);
        assertThat(resolver.resolve(request(null, null)))
                .isEqualTo(REMOTE);
    }
}
