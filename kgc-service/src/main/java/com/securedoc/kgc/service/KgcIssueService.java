package com.securedoc.kgc.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.securedoc.kgc.common.BusinessException;
import com.securedoc.kgc.common.ErrorCode;
import com.securedoc.kgc.entity.KgcPrivateKeyIssue;
import com.securedoc.kgc.entity.UserKey;
import com.securedoc.kgc.mapper.KgcPrivateKeyIssueMapper;
import com.securedoc.kgc.mapper.ShadowUserMapper;
import com.securedoc.kgc.mapper.UserKeyMapper;
import com.securedoc.kgc.web.dto.IssuePrivateKeyRequest;
import com.securedoc.kgc.web.dto.IssuePrivateKeyResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * SM9 私钥签发服务（设计文档 §2.2.5 / §18.9.2）。
 *
 * 流程：校验用户与身份绑定 → 用主密钥按身份提取 de → Base64 封包 →
 * 落签发审计记录(kgc_private_key_issues) → 推进 user_keys 密钥状态 → 返回私钥包。
 * KGC 是 SM9 密钥生命周期的权威，故签发后同步把 user_keys.key_status 置 ISSUED/REISSUED。
 */
@Service
public class KgcIssueService {

    private static final Logger log = LoggerFactory.getLogger(KgcIssueService.class);
    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
    /** 身份格式 user:{tenantId}:{userId}:{email}（设计文档约定）。 */
    private static final Pattern IDENTITY = Pattern.compile("^user:[^:]+:\\d+:[^:@\\s]+@[^:@\\s]+$");

    private final Sm9MasterKeyService masterKey;
    private final UserKeyMapper userKeyMapper;
    private final KgcPrivateKeyIssueMapper issueMapper;
    private final KgcAuditService auditService;
    private final ShadowUserMapper shadowUserMapper;

    public KgcIssueService(Sm9MasterKeyService masterKey,
                           UserKeyMapper userKeyMapper,
                           KgcPrivateKeyIssueMapper issueMapper,
                           KgcAuditService auditService,
                           ShadowUserMapper shadowUserMapper) {
        this.masterKey = masterKey;
        this.userKeyMapper = userKeyMapper;
        this.issueMapper = issueMapper;
        this.auditService = auditService;
        this.shadowUserMapper = shadowUserMapper;
    }

    /**
     * 登记新用户的 SM9 身份（新用户开通，§2.4 KGC 身份权威）。幂等：同 userId+同 identity 重复登记直接成功；
     * 同 userId 但不同 identity → IDENTITY_MISMATCH（身份一经登记不可经此接口改写）。
     * 校验 identity 内嵌 userId 与请求 userId 一致，杜绝为他人登记身份。
     */
    @Transactional
    public void registerIdentity(Long userId, String identity, String clientIp) {
        if (!IDENTITY.matcher(identity).matches()) {
            throw new BusinessException(ErrorCode.IDENTITY_INVALID);
        }
        // identity = user:{tenantId}:{userId}:{email} → 第 3 段必须等于请求 userId
        String embedded = identity.split(":")[2];
        if (!String.valueOf(userId).equals(embedded)) {
            throw new BusinessException(ErrorCode.IDENTITY_MISMATCH, "identity 内嵌 userId 与请求不一致");
        }
        UserKey existing = userKeyMapper.selectOne(
                new LambdaQueryWrapper<UserKey>().eq(UserKey::getUserId, userId));
        if (existing != null) {
            if (existing.getSm9Identity().equals(identity)) {
                log.info("KGC 身份已登记（幂等）：userId={} identity={}", userId, identity);
                return;
            }
            throw new BusinessException(ErrorCode.IDENTITY_MISMATCH, "该用户已登记不同身份，禁止改写");
        }
        // 同一 identity 被其他 userId 占用 → 唯一约束 uk_user_keys_identity 兜底，这里显式查更友好
        UserKey byIdentity = userKeyMapper.selectOne(
                new LambdaQueryWrapper<UserKey>().eq(UserKey::getSm9Identity, identity));
        if (byIdentity != null) {
            throw new BusinessException(ErrorCode.IDENTITY_MISMATCH, "该身份标识已被其他用户占用");
        }
        // 满足 user_keys→users 外键：共库部署时 users 行已由应用服务器建好；
        // dev 双库(独立 H2)时补影子占位行（无效密码哈希，KGC 不做认证）
        if (shadowUserMapper.countById(userId) == 0) {
            shadowUserMapper.insertShadow(userId, "kgc_shadow_" + userId);
            log.info("KGC 库补影子用户占位行 userId={}（dev 双库场景）", userId);
        }
        UserKey uk = new UserKey();
        uk.setUserId(userId);
        uk.setSm9Identity(identity);
        uk.setKeyStatus("UNINITIALIZED");
        uk.setDeviceBound(false);
        userKeyMapper.insert(uk);
        auditService.record(userId, "KGC_REGISTER", identity, clientIp, "登记 SM9 身份 " + identity);
        log.info("KGC 已登记身份：userId={} identity={}", userId, identity);
    }

    /** 首次签发。 */
    @Transactional
    public IssuePrivateKeyResponse issue(IssuePrivateKeyRequest req, String clientIp) {
        return doIssue(req, clientIp, false);
    }

    /** 重新签发（换设备/恢复）。 */
    @Transactional
    public IssuePrivateKeyResponse reissue(IssuePrivateKeyRequest req, String clientIp) {
        return doIssue(req, clientIp, true);
    }

    private IssuePrivateKeyResponse doIssue(IssuePrivateKeyRequest req, String clientIp, boolean reissue) {
        // 身份格式校验 user:{tenantId}:{userId}:{email}
        if (!IDENTITY.matcher(req.identity()).matches()) {
            throw new BusinessException(ErrorCode.IDENTITY_INVALID);
        }
        UserKey uk = userKeyMapper.selectOne(
                new LambdaQueryWrapper<UserKey>().eq(UserKey::getUserId, req.userId()));
        if (uk == null) {
            throw new BusinessException(ErrorCode.USER_NOT_FOUND);
        }
        // 身份绑定校验：只能为该用户已登记的 SM9 身份签发，杜绝为伪造身份发钥
        if (!uk.getSm9Identity().equals(req.identity())) {
            throw new BusinessException(ErrorCode.IDENTITY_MISMATCH);
        }

        // 用主密钥按身份提取 SM9 加密私钥 de（主私钥不出 Sm9MasterKeyService）
        byte[] de = masterKey.extractPrivateKey(req.identity().getBytes(StandardCharsets.UTF_8));
        String privateKeyPackage = Base64.getEncoder().encodeToString(de);

        // 落签发审计记录
        KgcPrivateKeyIssue rec = new KgcPrivateKeyIssue();
        rec.setId(UUID.randomUUID().toString());
        rec.setUserId(req.userId());
        rec.setSm9Identity(req.identity());
        rec.setIssueType(reissue ? "REISSUE" : "FIRST");
        rec.setDeviceFingerprint(req.deviceFingerprint());
        rec.setReason(req.reason());
        rec.setOperatorId(req.userId());            // 自助签发：操作人即用户本人
        rec.setClientIp(clientIp);
        rec.setAuditStatus("RECORDED");
        issueMapper.insert(rec);

        // 推进用户密钥状态
        uk.setKeyStatus(reissue ? "REISSUED" : "ISSUED");
        uk.setDeviceBound(req.deviceFingerprint() != null && !req.deviceFingerprint().isBlank());
        uk.setLastIssueTime(LocalDateTime.now());
        userKeyMapper.updateById(uk);

        // 写通用审计流（best-effort）
        auditService.record(req.userId(), reissue ? "KGC_REISSUE" : "KGC_ISSUE",
                rec.getId(), clientIp, "为 " + req.identity() + " 签发 SM9 私钥");

        log.info("KGC 已为 userId={} identity={} 签发私钥（type={}, issueId={}）",
                req.userId(), req.identity(), rec.getIssueType(), rec.getId());

        String issuedAt = rec.getIssuedAt().atZone(ZoneId.systemDefault()).toOffsetDateTime().format(ISO);
        return new IssuePrivateKeyResponse(rec.getId(), req.userId(), req.identity(), privateKeyPackage, issuedAt);
    }
}
