package com.securedoc.app.common;

/**
 * 统一错误码（对应设计文档 §2.11）。code 即枚举名，附带 HTTP 状态与默认中文消息。
 */
public enum ErrorCode {

    INVALID_CREDENTIALS(401, "用户名或密码错误"),
    AUTH_REQUIRED(401, "请先登录"),
    PERMISSION_DENIED(403, "权限不足"),
    USER_DISABLED(403, "账号已被禁用或锁定"),
    NOT_RECIPIENT(403, "您不是该文件的接收人"),
    FILE_NOT_FOUND(404, "文件不存在"),
    KEY_NOT_INITIALIZED(400, "用户密钥未初始化"),
    UPLOAD_INCOMPLETE(400, "分块上传未完成"),
    KGC_UNAVAILABLE(503, "KGC 服务不可用"),
    RATE_LIMITED(429, "请求过于频繁，请稍后再试"),
    INVALID_REQUEST(400, "请求参数非法"),
    INTERNAL_ERROR(500, "服务器内部错误");

    public final int httpStatus;
    public final String defaultMessage;

    ErrorCode(int httpStatus, String defaultMessage) {
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }
}
