package com.securedoc.kgc.web;

import com.securedoc.kgc.common.ApiResponse;
import com.securedoc.kgc.common.PageResult;
import com.securedoc.kgc.entity.KgcPrivateKeyIssue;
import com.securedoc.kgc.service.KgcIssueService;
import com.securedoc.kgc.service.KgcQueryService;
import com.securedoc.kgc.service.Sm9MasterKeyService;
import com.securedoc.kgc.web.dto.IdentityResponse;
import com.securedoc.kgc.web.dto.IssuePrivateKeyRequest;
import com.securedoc.kgc.web.dto.IssuePrivateKeyResponse;
import com.securedoc.kgc.web.dto.MasterPublicKeyResponse;
import com.securedoc.kgc.web.dto.RegisterIdentityRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * KGC SM9 接口（设计文档 §2.4）：私钥签发 / 重新签发 / 主公钥 / 身份 / 签发记录查询。
 */
@RestController
@RequestMapping("/kgc/sm9")
public class KgcSm9Controller {

    private final KgcIssueService issueService;
    private final KgcQueryService queryService;
    private final Sm9MasterKeyService masterKey;

    public KgcSm9Controller(KgcIssueService issueService,
                            KgcQueryService queryService,
                            Sm9MasterKeyService masterKey) {
        this.issueService = issueService;
        this.queryService = queryService;
        this.masterKey = masterKey;
    }

    /** 登记新用户 SM9 身份（新用户开通；应用服务器经令牌调用）。 */
    @PostMapping("/register-identity")
    public ApiResponse<IdentityResponse> registerIdentity(@Valid @RequestBody RegisterIdentityRequest req,
                                                          HttpServletRequest http) {
        issueService.registerIdentity(req.userId(), req.identity(), http.getRemoteAddr());
        return ApiResponse.ok(new IdentityResponse(req.userId(), req.identity()));
    }

    /** 首次签发 SM9 用户私钥。 */
    @PostMapping("/issue-private-key")
    public ApiResponse<IssuePrivateKeyResponse> issue(@Valid @RequestBody IssuePrivateKeyRequest req,
                                                      HttpServletRequest http) {
        return ApiResponse.ok(issueService.issue(req, http.getRemoteAddr()));
    }

    /** 重新签发（换设备/恢复）。 */
    @PostMapping("/reissue-private-key")
    public ApiResponse<IssuePrivateKeyResponse> reissue(@Valid @RequestBody IssuePrivateKeyRequest req,
                                                        HttpServletRequest http) {
        return ApiResponse.ok(issueService.reissue(req, http.getRemoteAddr()));
    }

    /** 主公钥 Ppub_e（公开信息，供发送方封装）。 */
    @GetMapping("/master-public-key")
    public ApiResponse<MasterPublicKeyResponse> masterPublicKey() {
        return ApiResponse.ok(new MasterPublicKeyResponse(
                masterKey.masterPublicKeyBase64(), masterKey.keyVersion()));
    }

    /** 查用户 SM9 身份标识。 */
    @GetMapping("/identity/{userId}")
    public ApiResponse<IdentityResponse> identity(@PathVariable Long userId) {
        return ApiResponse.ok(new IdentityResponse(userId, queryService.identityOf(userId)));
    }

    /** 分页查询签发记录（审计页用）。 */
    @GetMapping("/issues")
    public ApiResponse<PageResult<KgcPrivateKeyIssue>> issues(
            @RequestParam(defaultValue = "1") long page,
            @RequestParam(defaultValue = "20") long size,
            @RequestParam(required = false) Long userId) {
        return ApiResponse.ok(queryService.listIssues(page, size, userId));
    }
}
