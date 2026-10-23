package com.securedoc.app.common;

/**
 * 统一响应包装（BE-1）。所有接口返回 {success, code, message, data}。
 * 成功 code=SUCCESS；失败 code 为 §2.11 错误码（如 AUTH_REQUIRED）。
 */
public class ApiResponse<T> {

    private final boolean success;
    private final String code;
    private final String message;
    private final T data;

    private ApiResponse(boolean success, String code, String message, T data) {
        this.success = success;
        this.code = code;
        this.message = message;
        this.data = data;
    }

    public static <T> ApiResponse<T> ok(T data) {
        return new ApiResponse<>(true, "SUCCESS", "ok", data);
    }

    public static ApiResponse<Void> ok() {
        return new ApiResponse<>(true, "SUCCESS", "ok", null);
    }

    public static <T> ApiResponse<T> error(String code, String message) {
        return new ApiResponse<>(false, code, message, null);
    }

    public boolean isSuccess() { return success; }
    public String getCode() { return code; }
    public String getMessage() { return message; }
    public T getData() { return data; }
}
