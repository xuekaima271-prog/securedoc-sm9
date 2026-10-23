package com.securedoc.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.securedoc.app.entity.SecurityEvent;
import org.apache.ibatis.annotations.Mapper;

/** security_events 表 Mapper。 */
@Mapper
public interface SecurityEventMapper extends BaseMapper<SecurityEvent> {
}
