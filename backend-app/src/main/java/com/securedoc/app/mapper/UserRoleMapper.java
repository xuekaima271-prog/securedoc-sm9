package com.securedoc.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.securedoc.app.entity.UserRole;
import com.securedoc.app.mapper.dto.UserRoleCodeView;
import org.apache.ibatis.annotations.Select;

import java.util.List;

public interface UserRoleMapper extends BaseMapper<UserRole> {

    /** 一次性取全部 (userId, roleCode)，在服务层分组，避免 N+1。 */
    @Select("SELECT ur.user_id, r.role_code FROM user_roles ur JOIN roles r ON r.id = ur.role_id")
    List<UserRoleCodeView> selectAllRoleCodes();
}
