package com.securedoc.app.common;

/**
 * 审计哈希链校验结果（§2.2.11 / §13 防篡改审计）。
 * valid=true 表示从创世到末条逐条哈希自洽；否则 brokenAtId 指出首个被篡改/断裂的记录。
 */
public record AuditChainResult(
        boolean valid,
        long total,
        Long brokenAtId,
        String message
) {}
