package com.lms.security;

import com.lms.entity.Permission;
import com.lms.entity.Role;
import com.lms.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@AllArgsConstructor
public class CustomUserDetails implements UserDetails {
    
    private Long userId;
    private String email;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    private boolean enabled;
    private boolean emailVerified;
    
    public static CustomUserDetails build(User user) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        // Add role authorities
        for (Role role : user.getRoles()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getRoleName().toUpperCase()));
            
            // Add permission authorities
            for (Permission permission : role.getPermissions()) {
                authorities.add(new SimpleGrantedAuthority(permission.getPermissionName()));
            }
        }
        
        return new CustomUserDetails(
                user.getUserId(),
                user.getEmail(),
                user.getPasswordHash(),
                authorities,
                user.getStatus() == User.UserStatus.active,
                user.getEmailVerified()
        );
    }
    
    @Override
    public String getUsername() {
        return email;
    }
    
    @Override
    public String getPassword() {
        return password;
    }
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
    
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    
    @Override
    public boolean isAccountNonLocked() {
        return enabled;
    }
    
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    
    @Override
    public boolean isEnabled() {
        return enabled;
    }
}