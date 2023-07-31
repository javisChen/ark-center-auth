package com.ark.center.auth.infra.authentication.login;

import com.ark.center.auth.domain.user.AuthUser;
import com.ark.center.auth.domain.user.gateway.UserGateway;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;

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
        LoginUser loginUser = new LoginUser(user.getUsername(), user.getPassword(), true, true,
                true, true, Collections.emptyList());
        loginUser.setUserId(user.getId());
        loginUser.setUserCode(user.getUserCode());
        loginUser.setIsSuperAdmin(user.getIsSuperAdmin());
        return loginUser;
    }

}
