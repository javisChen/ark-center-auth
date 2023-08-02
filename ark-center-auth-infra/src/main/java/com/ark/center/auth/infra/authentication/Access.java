package com.ark.center.auth.infra.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component("access")
public class Access {

    public boolean test(HttpServletRequest request, Authentication authentication) {
        return true;
    }
}
