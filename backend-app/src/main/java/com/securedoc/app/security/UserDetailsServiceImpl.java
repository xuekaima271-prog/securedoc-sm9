package com.securedoc.app.security;

import com.securedoc.app.entity.User;
import com.securedoc.app.mapper.RoleMapper;
import com.securedoc.app.mapper.UserMapper;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/** 从数据库加载用户与角色，供 Spring Security 认证。角色映射为 ROLE_xxx 权限。 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserMapper userMapper;
    private final RoleMapper roleMapper;

    public UserDetailsServiceImpl(UserMapper userMapper, RoleMapper roleMapper) {
        this.userMapper = userMapper;
        this.roleMapper = roleMapper;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User u = userMapper.selectByUsername(username);
        if (u == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        List<SimpleGrantedAuthority> authorities = roleMapper.selectRoleCodesByUserId(u.getId())
                .stream()
                .map(code -> new SimpleGrantedAuthority("ROLE_" + code))
                .toList();
        boolean active = "ACTIVE".equals(u.getStatus());
        boolean locked = "LOCKED".equals(u.getStatus());
        return new SecurityUser(u.getId(), u.getUsername(), u.getPasswordHash(), active, locked, authorities);
    }
}
