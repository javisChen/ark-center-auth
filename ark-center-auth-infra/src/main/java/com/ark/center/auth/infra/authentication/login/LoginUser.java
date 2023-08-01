package com.ark.center.auth.infra.authentication.login;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Set;

@Setter
@Getter
public class LoginUser implements UserDetails, CredentialsContainer {

    private Long userId;
    private String userCode;
    private Boolean isSuperAdmin;
    private String password;
    private String username;
    private Set<GrantedAuthority> authorities;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;

    @Override
    public void eraseCredentials() {
        this.password = null;
    }
}
