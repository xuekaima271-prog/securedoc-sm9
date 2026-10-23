package com.securedoc.app.web;

import com.securedoc.app.common.ApiResponse;
import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ClientIpResolver;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.security.SecurityUser;
import com.securedoc.app.service.KeyService;
import com.securedoc.app.service.LoginThrottleService;
import com.securedoc.app.web.dto.KeyInitRequest;
import com.securedoc.app.web.dto.KeyInitResponse;
import com.securedoc.app.web.dto.KeyStatusResponse;
import com.securedoc.app.web.dto.MasterPublicKeyResponse;
import com.securedoc.app.web.dto.RecipientView;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 密钥接口（§2.10 / §6）。浏览器只与本应用通信；KGC 令牌与签发逻辑全在服务端。
 * /init 只签发会话用户自己的身份，私钥包仅中转返回浏览器（存 IndexedDB），不落库。
 */
@RestController
@RequestMapping("/api/keys")
public class KeyController {

    private final KeyService keyService;
    private final AuthenticationManager authenticationManager;
    private final LoginThrottleService throttle;
    private final ClientIpResolver clientIpResolver;

    public KeyController(KeyService keyService, AuthenticationManager authenticationManager,
                         LoginThrottleService throttle, ClientIpResolver clientIpResolver) {
        this.keyService = keyService;
        this.authenticationManager = authenticationManager;
        this.throttle = throttle;
        this.clientIpResolver = clientIpResolver;
    }

    /** 当前用户密钥状态（密钥初始化页）。 */
    @GetMapping("/me/status")
    public ApiResponse<KeyStatusResponse> myStatus(@AuthenticationPrincipal SecurityUser user) {
        return ApiResponse.ok(keyService.meStatus(user.getUserId()));
    }

    /** SM9 主公钥（发送页封装 DEK 用）。 */
    @GetMapping("/master-public-key")
    public ApiResponse<MasterPublicKeyResponse> masterPublicKey() {
        return ApiResponse.ok(new MasterPublicKeyResponse(keyService.masterPublicKey()));
    }

    /** 可选接收人列表（发送页选人）。 */
    @GetMapping("/recipients")
    public ApiResponse<List<RecipientView>> recipients(@AuthenticationPrincipal SecurityUser user) {
        return ApiResponse.ok(keyService.recipients(user.getUserId()));
    }

    /** 初始化/重签发当前用户 SM9 私钥（代理 KGC）。 */
    @PostMapping("/init")
    public ApiResponse<KeyInitResponse> init(@Valid @RequestBody KeyInitRequest req,
                                             @AuthenticationPrincipal SecurityUser user,
                                             HttpServletRequest http) {
        String ip = clientIpResolver.resolve(http);
        throttle.assertAllowed(user.getUsername(), ip);
        try {
            // A session alone must not be enough to bypass the locked local key vault.
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    user.getUsername(), req.password()));
        } catch (AuthenticationException e) {
            throttle.recordFailure(user.getUsername(), ip);
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
        }
        throttle.recordSuccess(user.getUsername());
        return ApiResponse.ok(keyService.initKey(user.getUserId(), req.deviceFingerprint(), ip));
    }
}
