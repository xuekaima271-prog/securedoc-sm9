package com.securedoc.kgc.mapper;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

/**
 * KGC 库 users 表的最小访问（仅为满足 user_keys→users 外键）。
 *
 * 背景：生产为共库部署，应用服务器先建 users 行，KGC 登记 user_keys 时 FK 天然满足；
 * dev 为双 H2 独立库，KGC 库没有新用户的 users 行 → 登记前需补「影子占位行」。
 * 占位行 password_hash 为无效值（非 BCrypt），KGC 不做账号认证，不可能被用于登录。
 */
@Mapper
public interface ShadowUserMapper {

    @Select("SELECT COUNT(*) FROM users WHERE id = #{userId}")
    long countById(@Param("userId") Long userId);

    @Insert("INSERT INTO users (id, username, password_hash, real_name, status) " +
            "VALUES (#{userId}, #{username}, '!kgc-shadow-no-login!', 'KGC影子占位', 'ACTIVE')")
    int insertShadow(@Param("userId") Long userId, @Param("username") String username);
}
