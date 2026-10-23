package com.securedoc.app.config;

import com.securedoc.app.security.RestAccessDeniedHandler;
import com.securedoc.app.security.RestAuthEntryPoint;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.header.writers.DelegatingRequestMatcherHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * 安全配置（Step 3.3 + Step 6）。会话认证 + 统一 401/403 JSON + CORS。
 * SEC-1 决策（ADR）：dev 关闭 CSRF——前端 Vite(:5173) 跨域携带 Cookie 调用，CORS 白名单仅放行
 *   指定 Origin 且 allowCredentials=true（不可用 "*"）。生产应改：Cookie SameSite=Strict/Lax +
 *   CSRF Token（或改 header 鉴权）。本机演示无第三方站点诱导，CSRF 风险可接受并已在论文标注。
 */
@Configuration
@EnableMethodSecurity   // 启用 @PreAuthorize（RBAC 方法级鉴权）
public class SecurityConfig {

    private static final String API_CONTENT_SECURITY_POLICY =
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

    @Value("${securedoc.cors.allowed-origins:http://localhost:5173}")
    private String allowedOrigins;

    /** 与 init_data.sql 的 BCrypt($2b$) 哈希匹配 */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /** 会话级 SecurityContext 存取（登录写入、后续请求读取） */
    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    /** 暴露 AuthenticationManager（基于自动装配的 DaoAuthenticationProvider：UserDetailsService + PasswordEncoder） */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           RestAuthEntryPoint authEntryPoint,
                                           RestAccessDeniedHandler accessDeniedHandler,
                                           SecurityContextRepository securityContextRepository) throws Exception {
        http
            // SEC-1（ADR）：dev 关闭 CSRF；CORS 白名单 + 凭证见类注释
            .csrf(csrf -> csrf.disable())
            .cors(Customizer.withDefaults())
            .headers(h -> h
                    // 保留 H2 控制台同源 iframe 支持；API 才应用禁用一切资源加载的 CSP。
                    .frameOptions(f -> f.sameOrigin())
                    .addHeaderWriter(apiHeader("Content-Security-Policy", API_CONTENT_SECURITY_POLICY))
                    .addHeaderWriter(apiHeader("Referrer-Policy", "no-referrer")))
            .securityContext(sc -> sc.securityContextRepository(securityContextRepository))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/health", "/api/auth/login", "/h2-console/**").permitAll()
                .anyRequest().authenticated())   // /api/auth/me 等需登录；角色级规则 3.4 再加
            .exceptionHandling(e -> e
                .authenticationEntryPoint(authEntryPoint)        // 401 AUTH_REQUIRED
                .accessDeniedHandler(accessDeniedHandler))       // 403 PERMISSION_DENIED
            .formLogin(f -> f.disable())
            .httpBasic(b -> b.disable())
            .logout(l -> l.disable());                            // 使用自定义 /api/auth/logout
        return http.build();
    }

    private static DelegatingRequestMatcherHeaderWriter apiHeader(String name, String value) {
        return new DelegatingRequestMatcherHeaderWriter(
                PathPatternRequestMatcher.withDefaults().matcher("/api/**"),
                new StaticHeadersWriter(name, value));
    }

    /** CORS（BE-5）：放行前端 Origin，允许携带 Cookie，并暴露下载分块的校验头供前端读取。 */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(Arrays.stream(allowedOrigins.split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).toList());
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("*"));
        cfg.setAllowCredentials(true);   // 携带 JSESSIONID Cookie
        cfg.setExposedHeaders(List.of("X-Chunk-Index", "X-Chunk-Digest", "X-Chunk-IV"));
        cfg.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }
}
