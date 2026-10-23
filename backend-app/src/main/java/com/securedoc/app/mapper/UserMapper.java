package com.securedoc.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.securedoc.app.entity.User;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface UserMapper extends BaseMapper<User> {

    /** 按登录账号查用户（登录用）。 */
    @Select("SELECT * FROM users WHERE username = #{username}")
    User selectByUsername(@Param("username") String username);
}
