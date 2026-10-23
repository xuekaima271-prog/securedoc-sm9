package com.securedoc.app.common;

import java.util.List;

/** 统一分页结果。 */
public record PageResult<T>(long total, long page, long size, List<T> records) {
}
