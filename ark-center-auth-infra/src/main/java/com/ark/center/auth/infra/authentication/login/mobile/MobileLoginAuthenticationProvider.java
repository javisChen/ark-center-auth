package com.ark.center.auth.infra.authentication.login.mobile;

import com.ark.center.auth.client.verifycode.command.VerifyCodeCommand;
import com.ark.center.auth.client.verifycode.common.VerifyCodeScene;
import com.ark.center.auth.client.verifycode.common.VerifyCodeType;
import com.ark.center.auth.infra.authentication.LoginAuthenticationDetails;
import com.ark.center.auth.infra.authentication.login.provider.UserDetailsAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.UserNotFoundException;
import com.ark.center.auth.infra.authentication.login.userdetails.AuthenticationUserService;
import com.ark.center.auth.infra.authentication.token.issuer.TokenIssuer;
import com.ark.center.auth.infra.verifycode.SmsVerifyCodeProvider;
import com.ark.component.security.base.authentication.AuthUser;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class MobileLoginAuthenticationProvider extends UserDetailsAuthenticationProvider {

    private final AuthenticationUserService authenticationUserService;
    private final SmsVerifyCodeProvider smsVerifyCodeProvider;

    public MobileLoginAuthenticationProvider(AuthenticationUserService authenticationUserService,
                                             TokenIssuer tokenIssuer,
                                             SmsVerifyCodeProvider smsVerifyCodeProvider) {
        super(tokenIssuer);
        this.authenticationUserService = authenticationUserService;
        this.smsVerifyCodeProvider = smsVerifyCodeProvider;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, Authentication authentication, LoginAuthenticationDetails details) throws AuthenticationException {
        if (authentication.getCredentials() == null || StringUtils.isBlank(authentication.getCredentials().toString())) {
            this.logger.debug("Failed to authenticate since no credentials provided");
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
        VerifyCodeCommand command = new VerifyCodeCommand();
        command.setType(VerifyCodeType.SMS);
        command.setTarget(authentication.getPrincipal().toString());
        command.setCode(authentication.getCredentials().toString());
        command.setScene(VerifyCodeScene.LOGIN);
        command.setVerifyCodeId(details.getBaseLoginAuthenticateRequest().getVerifyCodeId());
        if (!smsVerifyCodeProvider.verify(command)) {
            throw new BadCredentialsException(this.messages
                    .getMessage("UserDetailsAuthenticationProvider.captchaInvalid", "Bad credentials"));
        }
    }

    @Override
    protected AuthUser retrieveUser(String username, Authentication authentication) throws AuthenticationException {
        try {
            AuthUser loadedUser = authenticationUserService.loadUserByMobile(((String) authentication.getPrincipal()), authentication);
            if (loadedUser == null) {
                throw new InternalAuthenticationServiceException(
                        "UserDetailsService returned null, which is an interface contract violation");
            }
            return loadedUser;
        } catch (UserNotFoundException | InternalAuthenticationServiceException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MobileAuthenticationToken.class.isAssignableFrom(authentication);
    }
}