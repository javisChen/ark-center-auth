package com.ark.center.auth.infra.authentication;

import com.ark.center.auth.infra.application.model.ApplicationAuthConfig;
import com.ark.center.auth.infra.authentication.common.CommonConst;
import com.ark.center.auth.client.authentication.command.BaseLoginAuthenticateRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Getter
public class LoginAuthenticationDetails extends WebAuthenticationDetails {

    private final BaseLoginAuthenticateRequest baseLoginAuthenticateRequest;
    private final ApplicationAuthConfig applicationAuthConfig;

    public LoginAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.baseLoginAuthenticateRequest = (BaseLoginAuthenticateRequest) request.getAttribute(CommonConst.BASE_LOGIN_REQUEST);
        this.applicationAuthConfig = (ApplicationAuthConfig) request.getAttribute(CommonConst.APPLICATION_CONFIG);
    }

}
