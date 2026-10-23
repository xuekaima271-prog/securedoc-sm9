package com.securedoc.kgc.common;

/**
 * KGC 服务统一错误码。code 即枚举名，附带 HTTP 状态与默认中文消息。
 * 与设计文档 §2.11 错误码风格一致。
 */
public enum ErrorCode {

    KGC_UNAUTHORIZED(401, "KGC 服务令牌缺失或无效"),
    INVALID_REQUEST(400, "请求参数非法"),
    IDENTITY_INVALID(400, "SM9 身份标识格式非法"),
    IDENTITY_MISMATCH(400, "身份标识与用户不匹配"),
    USER_NOT_FOUND(404, "用户不存在"),
    MASTER_KEY_ERROR(500, "KGC 主密钥不可用"),
    INTERNAL_ERROR(500, "服务器内部错误");

    public final int httpStatus;
    public final String defaultMessage;

    ErrorCode(int httpStatus, String defaultMessage) {
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }
}
