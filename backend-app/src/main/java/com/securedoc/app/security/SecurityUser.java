package com.securedoc.app.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * 认证主体：在标准 UserDetails 基础上携带 userId，便于 /me 等接口直接取用户ID。
 * 注意：passwordHash 仅用于认证校验，不要序列化返回给前端。
 */
public class SecurityUser implements UserDetails {

    private final Long userId;
    private final String username;
    private final transient String passwordHash;
    private final boolean active;   // status == ACTIVE
    private final boolean locked;   // status == LOCKED
    private final Collection<? extends GrantedAuthority> authorities;

    public SecurityUser(Long userId, String username, String passwordHash,
                        boolean active, boolean locked,
                        Collection<? extends GrantedAuthority> authorities) {
        this.userId = userId;
        this.username = username;
        this.passwordHash = passwordHash;
        this.active = active;
        this.locked = locked;
        this.authorities = authorities;
    }

    public Long getUserId() { return userId; }

    @Override public Collection<? extends GrantedAuthority> getAuthorities() { return authorities; }
    @Override public String getPassword() { return passwordHash; }
    @Override public String getUsername() { return username; }
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return !locked; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return active; }
}
