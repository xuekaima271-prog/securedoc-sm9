package com.securedoc.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.securedoc.app.entity.UserKey;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface UserKeyMapper extends BaseMapper<UserKey> {

    /** 按 user_id 查密钥状态（user_id 唯一）。 */
    @Select("SELECT * FROM user_keys WHERE user_id = #{userId}")
    UserKey selectByUserId(@Param("userId") Long userId);
}
