package com.securedoc.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.securedoc.app.entity.AuditLog;
import org.apache.ibatis.annotations.Select;

public interface AuditLogMapper extends BaseMapper<AuditLog> {

    /** 取最新一条审计的 current_hash（哈希链尾），无记录返回 null。H2/MySQL 兼容 LIMIT。 */
    @Select("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    String selectLastHash();
}
