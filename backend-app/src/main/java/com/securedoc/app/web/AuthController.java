package com.securedoc.app.web;

import com.securedoc.app.common.ApiResponse;
import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ClientIpResolver;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.entity.UserKey;
import com.securedoc.app.mapper.UserKeyMapper;
import com.securedoc.app.security.SecurityUser;
import com.securedoc.app.service.AuditService;
import com.securedoc.app.service.LoginThrottleService;
import com.securedoc.app.web.dto.AuthUserInfo;
import com.securedoc.app.web.dto.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 认证接口（§2.2 / §18.9.1）。会话方案：认证成功后把 SecurityContext 存入 HttpSession，
 * 浏览器持 JSESSIONID（HttpOnly Cookie）后续免登录。不向前端返回任何密钥/哈希。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final UserKeyMapper userKeyMapper;
    private final LoginThrottleService throttle;
    private final AuditService auditService;
    private final ClientIpResolver clientIpResolver;

    public AuthController(AuthenticationManager authenticationManager,
                         SecurityContextRepository securityContextRepository,
                         UserKeyMapper userKeyMapper,
                         LoginThrottleService throttle,
                         AuditService auditService,
                         ClientIpResolver clientIpResolver) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
        this.userKeyMapper = userKeyMapper;
        this.throttle = throttle;
        this.auditService = auditService;
        this.clientIpResolver = clientIpResolver;
    }

    @PostMapping("/login")
    public ApiResponse<AuthUserInfo> login(@Valid @RequestBody LoginRequest req,
                                           HttpServletRequest request,
                                           HttpServletResponse response) {
        String ip = clientIpResolver.resolve(request);
        throttle.assertAllowed(req.username(), ip);   // 账号锁定 / IP 限流前置校验
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.username(), req.password()));
            // SEC-6 防会话固定：手动认证不经 Spring 登录过滤器，需丢弃登录前会话、强制新建 JSESSIONID
            HttpSession existing = request.getSession(false);
            if (existing != null) {
                existing.invalidate();
            }
            // 持久化到会话，使后续请求凭 JSESSIONID 即认证
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(auth);
            SecurityContextHolder.setContext(context);
            securityContextRepository.saveContext(context, request, response);
            throttle.recordSuccess(req.username());      // 成功：清零失败计数与锁定
            SecurityUser principal = (SecurityUser) auth.getPrincipal();
            auditService.record(principal.getUserId(), "LOGIN", "AUTH", req.username(),
                    ip, request.getHeader("User-Agent"), "登录成功");
            return ApiResponse.ok(toUserInfo(principal));
        } catch (BadCredentialsException | UsernameNotFoundException e) {
            throttle.recordFailure(req.username(), ip);  // 失败：计数+1，达阈值锁定
            auditService.record(null, "LOGIN_FAIL", "AUTH", req.username(),
                    ip, request.getHeader("User-Agent"), "用户名或密码错误");
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
        } catch (DisabledException | LockedException e) {
            throw new BusinessException(ErrorCode.USER_DISABLED);
        }
    }

    @GetMapping("/me")
    public ApiResponse<AuthUserInfo> me(@AuthenticationPrincipal SecurityUser principal) {
        if (principal == null) {
            throw new BusinessException(ErrorCode.AUTH_REQUIRED);
        }
        return ApiResponse.ok(toUserInfo(principal));
    }

    @PostMapping("/logout")
    public ApiResponse<Void> logout(HttpServletRequest request) {
        Authentication current = SecurityContextHolder.getContext().getAuthentication();
        Long actorId = (current != null && current.getPrincipal() instanceof SecurityUser su) ? su.getUserId() : null;
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        auditService.record(actorId, "LOGOUT", "AUTH", null,
                clientIpResolver.resolve(request), request.getHeader("User-Agent"), "登出");
        return ApiResponse.ok();
    }

    private AuthUserInfo toUserInfo(SecurityUser user) {
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(a -> a.startsWith("ROLE_") ? a.substring(5) : a)
                .toList();
        UserKey key = userKeyMapper.selectByUserId(user.getUserId());
        boolean keyInitialized = key != null
                && ("ISSUED".equals(key.getKeyStatus()) || "REISSUED".equals(key.getKeyStatus()));
        return new AuthUserInfo(user.getUserId(), user.getUsername(), roles, keyInitialized);
    }
}
