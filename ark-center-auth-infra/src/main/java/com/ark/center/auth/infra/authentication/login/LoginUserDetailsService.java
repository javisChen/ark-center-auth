package com.ark.center.auth.infra.authentication.login;

import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.auth.domain.user.gateway.UserGateway;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;
import java.util.Set;

public class LoginUserDetailsService implements UserDetailsService, InitializingBean {

    private final UserGateway userGateway;

    public LoginUserDetailsService(UserGateway userGateway) {
        this.userGateway = userGateway;
    }

    @Override
    public void afterPropertiesSet() {
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser user = userGateway.retrieveUserByUserName(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }
        LoginUser loginUser = buildLoginUser(user);
        loginUser.setAuthorities(Set.of(new SimpleGrantedAuthority("ROLE_S"),new SimpleGrantedAuthority("ROLE_D")));
        return loginUser;
    }

    private LoginUser buildLoginUser(AuthUser user) {
        LoginUser loginUser = new LoginUser();
        loginUser.setUsername(user.getUsername());
        loginUser.setPassword(user.getPassword());
        loginUser.setAccountNonExpired(true);
        loginUser.setAccountNonLocked(true);
        loginUser.setEnabled(true);
        loginUser.setCredentialsNonExpired(true);
        loginUser.setAuthorities(Collections.emptySet());
        loginUser.setUserId(user.getId());
        loginUser.setUserCode(user.getUserCode());
        loginUser.setIsSuperAdmin(user.getIsSuperAdmin());
        return loginUser;
    }

}
