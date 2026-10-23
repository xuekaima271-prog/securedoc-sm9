package com.securedoc.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.securedoc.app.entity.Role;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

public interface RoleMapper extends BaseMapper<Role> {

    /** 查某用户的全部角色编码（RBAC 用）。 */
    @Select("SELECT r.role_code FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = #{userId}")
    List<String> selectRoleCodesByUserId(@Param("userId") Long userId);
}
