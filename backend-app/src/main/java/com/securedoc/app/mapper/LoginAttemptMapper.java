package com.securedoc.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.securedoc.app.entity.LoginAttempt;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface LoginAttemptMapper extends BaseMapper<LoginAttempt> {

    @Select("SELECT * FROM login_attempts WHERE username = #{username}")
    LoginAttempt selectByUsername(@Param("username") String username);
}
