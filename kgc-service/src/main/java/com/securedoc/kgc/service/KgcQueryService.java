package com.securedoc.kgc.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.securedoc.kgc.common.BusinessException;
import com.securedoc.kgc.common.ErrorCode;
import com.securedoc.kgc.common.PageResult;
import com.securedoc.kgc.entity.KgcPrivateKeyIssue;
import com.securedoc.kgc.entity.UserKey;
import com.securedoc.kgc.mapper.KgcPrivateKeyIssueMapper;
import com.securedoc.kgc.mapper.UserKeyMapper;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * KGC 读侧服务：用户 SM9 身份查询、签发记录分页查询（供审计页展示）。
 * 分页用 selectCount + LIMIT 手动实现（与 backend-app 一致，不依赖分页插件）。
 */
@Service
public class KgcQueryService {

    private final UserKeyMapper userKeyMapper;
    private final KgcPrivateKeyIssueMapper issueMapper;

    public KgcQueryService(UserKeyMapper userKeyMapper, KgcPrivateKeyIssueMapper issueMapper) {
        this.userKeyMapper = userKeyMapper;
        this.issueMapper = issueMapper;
    }

    /** 查用户登记的 SM9 身份标识。 */
    public String identityOf(Long userId) {
        UserKey uk = userKeyMapper.selectOne(
                new LambdaQueryWrapper<UserKey>().eq(UserKey::getUserId, userId));
        if (uk == null) {
            throw new BusinessException(ErrorCode.USER_NOT_FOUND);
        }
        return uk.getSm9Identity();
    }

    /** 分页查询签发记录（按签发时间倒序），可选按 userId 过滤。 */
    public PageResult<KgcPrivateKeyIssue> listIssues(long page, long size, Long userId) {
        long safePage = page < 1 ? 1 : page;
        long safeSize = (size < 1 || size > 200) ? 20 : size;

        LambdaQueryWrapper<KgcPrivateKeyIssue> w = new LambdaQueryWrapper<>();
        if (userId != null) {
            w.eq(KgcPrivateKeyIssue::getUserId, userId);
        }
        long total = issueMapper.selectCount(w);

        w.orderByDesc(KgcPrivateKeyIssue::getIssuedAt);
        w.last("LIMIT " + ((safePage - 1) * safeSize) + ", " + safeSize);
        List<KgcPrivateKeyIssue> records = total == 0 ? List.of() : issueMapper.selectList(w);

        return new PageResult<>(total, safePage, safeSize, records);
    }
}
