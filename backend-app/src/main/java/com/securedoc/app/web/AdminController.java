package com.securedoc.app.web;

import com.securedoc.app.common.ApiResponse;
import com.securedoc.app.common.ClientIpResolver;
import com.securedoc.app.security.SecurityUser;
import com.securedoc.app.service.AdminFileService;
import com.securedoc.app.service.AdminUserService;
import com.securedoc.app.web.dto.AdminFileView;
import com.securedoc.app.web.dto.CreateUserRequest;
import com.securedoc.app.web.dto.UpdateUserRolesRequest;
import com.securedoc.app.web.dto.UpdateUserStatusRequest;
import com.securedoc.app.web.dto.UserSummary;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** 管理员接口（§2.9）。仅 SYS_ADMIN 可访问；只返回密文视角，绝不含明文/密钥。 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AdminUserService adminUserService;
    private final AdminFileService adminFileService;
    private final com.securedoc.app.client.KgcClient kgcClient;
    private final ClientIpResolver clientIpResolver;

    public AdminController(AdminUserService adminUserService, AdminFileService adminFileService,
                           com.securedoc.app.client.KgcClient kgcClient,
                           ClientIpResolver clientIpResolver) {
        this.adminUserService = adminUserService;
        this.adminFileService = adminFileService;
        this.kgcClient = kgcClient;
        this.clientIpResolver = clientIpResolver;
    }

    /**
     * KGC 私钥签发记录（§2.4 签发审计/KGC_ADMIN 简化实现：管理员与审计员可查）。
     * 经服务端令牌代理 KGC /kgc/sm9/issues，浏览器不接触 KGC 令牌；记录含 issueType(FIRST/REISSUE)。
     */
    @GetMapping("/kgc-issues")
    @PreAuthorize("hasAnyRole('SYS_ADMIN','SECURITY_AUDITOR')")
    public ApiResponse<com.fasterxml.jackson.databind.JsonNode> kgcIssues(
            @org.springframework.web.bind.annotation.RequestParam(defaultValue = "1") long page,
            @org.springframework.web.bind.annotation.RequestParam(defaultValue = "20") long size,
            @org.springframework.web.bind.annotation.RequestParam(required = false) Long userId) {
        return ApiResponse.ok(kgcClient.listIssues(page, size, userId));
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('SYS_ADMIN')")
    public ApiResponse<List<UserSummary>> listUsers() {
        return ApiResponse.ok(adminUserService.listUsers());
    }

    /** 密文记录页（§2.10 必做）：列出全部文件密文记录，证明管理员可审计、不可解密。 */
    @GetMapping("/files")
    @PreAuthorize("hasRole('SYS_ADMIN')")
    public ApiResponse<List<AdminFileView>> listFiles() {
        return ApiResponse.ok(adminFileService.listFiles());
    }

    /** 新增用户（§2.3）：建账号+分配角色+生成 SM9 身份并登记到 KGC。 */
    @PostMapping("/users")
    @PreAuthorize("hasRole('SYS_ADMIN')")
    public ApiResponse<UserSummary> createUser(@Valid @RequestBody CreateUserRequest req,
                                               @AuthenticationPrincipal SecurityUser admin,
                                               HttpServletRequest http) {
        return ApiResponse.ok(adminUserService.createUser(admin.getUserId(), req, clientIpResolver.resolve(http)));
    }

    /** 启停用户（§2.3 / BE-7）：ACTIVE/DISABLED/LOCKED。 */
    @PutMapping("/users/{id}/status")
    @PreAuthorize("hasRole('SYS_ADMIN')")
    public ApiResponse<Void> updateStatus(@PathVariable Long id,
                                          @Valid @RequestBody UpdateUserStatusRequest req,
                                          @AuthenticationPrincipal SecurityUser admin,
                                          HttpServletRequest http) {
        adminUserService.updateStatus(admin.getUserId(), id, req.status(), clientIpResolver.resolve(http));
        return ApiResponse.ok();
    }

    /** 改用户角色（§2.3 / BE-7）：整集替换。 */
    @PutMapping("/users/{id}/roles")
    @PreAuthorize("hasRole('SYS_ADMIN')")
    public ApiResponse<Void> updateRoles(@PathVariable Long id,
                                         @Valid @RequestBody UpdateUserRolesRequest req,
                                         @AuthenticationPrincipal SecurityUser admin,
                                         HttpServletRequest http) {
        adminUserService.updateRoles(admin.getUserId(), id, req.roleCodes(), clientIpResolver.resolve(http));
        return ApiResponse.ok();
    }
}
