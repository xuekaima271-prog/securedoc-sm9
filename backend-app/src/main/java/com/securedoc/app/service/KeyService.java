package com.securedoc.app.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.securedoc.app.client.KgcClient;
import com.securedoc.app.common.BusinessException;
import com.securedoc.app.common.ErrorCode;
import com.securedoc.app.entity.User;
import com.securedoc.app.entity.UserKey;
import com.securedoc.app.mapper.UserKeyMapper;
import com.securedoc.app.mapper.UserMapper;
import com.securedoc.app.web.dto.KeyInitResponse;
import com.securedoc.app.web.dto.KeyStatusResponse;
import com.securedoc.app.web.dto.RecipientView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 密钥编排（Step 6）：状态查询、可选接收人列表、密钥初始化（代理 KGC 签发）。
 * 安全核心：initKey 只用「当前会话用户」的身份去 KGC 签发，调用者无法为他人申请私钥；
 * KGC 令牌只在服务端；私钥包仅中转、不落库。
 */
@Service
public class KeyService {

    private static final Logger log = LoggerFactory.getLogger(KeyService.class);

    private final UserKeyMapper userKeyMapper;
    private final UserMapper userMapper;
    private final KgcClient kgcClient;
    private final AuditService auditService;

    public KeyService(UserKeyMapper userKeyMapper, UserMapper userMapper,
                      KgcClient kgcClient, AuditService auditService) {
        this.userKeyMapper = userKeyMapper;
        this.userMapper = userMapper;
        this.kgcClient = kgcClient;
        this.auditService = auditService;
    }

    private static boolean isInitialized(String status) {
        return "ISSUED".equals(status) || "REISSUED".equals(status);
    }

    /** 当前用户密钥状态。 */
    public KeyStatusResponse meStatus(Long userId) {
        UserKey uk = userKeyMapper.selectByUserId(userId);
        if (uk == null) {
            throw new BusinessException(ErrorCode.KEY_NOT_INITIALIZED, "未找到用户密钥记录");
        }
        return new KeyStatusResponse(userId, uk.getSm9Identity(), uk.getKeyStatus(),
                Boolean.TRUE.equals(uk.getDeviceBound()), isInitialized(uk.getKeyStatus()));
    }

    /** SM9 主公钥（经 KGC 代理，缓存）。 */
    public String masterPublicKey() {
        return kgcClient.getMasterPublicKey();
    }

    /** 可选接收人（除自己外的全部用户密钥），用于发送页选人。 */
    public List<RecipientView> recipients(Long selfUserId) {
        List<UserKey> keys = userKeyMapper.selectList(null);
        if (keys.isEmpty()) return List.of();
        Map<Long, User> userById = userMapper.selectList(null).stream()
                .collect(Collectors.toMap(User::getId, Function.identity()));
        return keys.stream()
                .filter(k -> !k.getUserId().equals(selfUserId))
                .map(k -> {
                    User u = userById.get(k.getUserId());
                    return new RecipientView(k.getUserId(),
                            u == null ? null : u.getUsername(),
                            u == null ? null : u.getRealName(),
                            k.getSm9Identity(), k.getKeyStatus());
                })
                .toList();
    }

    /**
     * 初始化（或重签发）当前用户的 SM9 私钥：代理 KGC，仅用会话用户自己的身份。
     * 首次走 KGC /issue-private-key；已初始化(换设备/恢复)走 /reissue-private-key（§2.4，
     * KGC 侧落 issue_type=REISSUE，两侧审计一致）。私钥包不落库，仅返回浏览器。
     */
    @Transactional
    public KeyInitResponse initKey(Long userId, String deviceFingerprint, String clientIp) {
        UserKey uk = userKeyMapper.selectByUserId(userId);
        if (uk == null) {
            throw new BusinessException(ErrorCode.KEY_NOT_INITIALIZED, "未找到用户密钥记录");
        }
        String identity = uk.getSm9Identity();
        boolean firstTime = !isInitialized(uk.getKeyStatus());

        JsonNode data = firstTime
                ? kgcClient.issuePrivateKey(userId, identity, deviceFingerprint)
                : kgcClient.reissuePrivateKey(userId, identity, deviceFingerprint, "用户重新初始化（换设备/恢复）");
        String pkg = data.path("privateKeyPackage").asText(null);
        String issueId = data.path("issueId").asText(null);
        String issuedAt = data.path("issuedAt").asText(null);
        if (pkg == null || pkg.isBlank()) {
            throw new BusinessException(ErrorCode.KGC_UNAVAILABLE, "KGC 未返回私钥包");
        }

        uk.setKeyStatus(firstTime ? "ISSUED" : "REISSUED");
        uk.setDeviceBound(true);
        uk.setLastIssueTime(LocalDateTime.now());
        userKeyMapper.updateById(uk);

        auditService.record(userId, firstTime ? "KGC_ISSUE" : "KGC_REISSUE", "KEY",
                String.valueOf(userId), clientIp, null,
                (firstTime ? "首次签发" : "重签发") + " SM9 私钥, issueId=" + issueId);
        log.info("key-init: userId={} identity={} type={} issueId={}",
                userId, identity, firstTime ? "FIRST" : "REISSUE", issueId);
        return new KeyInitResponse(userId, identity, pkg, issueId, issuedAt);
    }
}
