package com.ark.center.auth.infra.authentication.login.mobile;

import com.ark.center.auth.client.captcha.command.VerifyCaptchaCommand;
import com.ark.center.auth.client.captcha.common.CaptchaScene;
import com.ark.center.auth.client.captcha.common.CaptchaType;
import com.ark.center.auth.infra.authentication.login.provider.UserDetailsAuthenticationProvider;
import com.ark.center.auth.infra.authentication.login.UserNotFoundException;
import com.ark.center.auth.infra.authentication.login.userdetails.IamUserDetailsService;
import com.ark.center.auth.infra.authentication.token.issuer.TokenIssuer;
import com.ark.center.auth.infra.captcha.SmsCaptchaProvider;
import com.ark.component.security.base.authentication.AuthUser;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class MobileLoginAuthenticationProvider extends UserDetailsAuthenticationProvider {

    private final IamUserDetailsService iamUserDetailsService;

    private final SmsCaptchaProvider smsCaptchaProvider;


    public MobileLoginAuthenticationProvider(IamUserDetailsService iamUserDetailsService,
                                             TokenIssuer tokenIssuer,
                                             SmsCaptchaProvider smsCaptchaProvider) {
        super(tokenIssuer);
        this.iamUserDetailsService = iamUserDetailsService;
        this.smsCaptchaProvider = smsCaptchaProvider;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, Authentication authentication) throws AuthenticationException {
        if (authentication.getCredentials() == null || StringUtils.isBlank(authentication.getCredentials().toString())) {
            this.logger.debug("Failed to authenticate since no credentials provided");
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }

        VerifyCaptchaCommand command = new VerifyCaptchaCommand();
        command.setType(CaptchaType.SMS);
        command.setTarget(authentication.getPrincipal().toString());
        command.setCode(authentication.getCredentials().toString());
        command.setScene(CaptchaScene.LOGIN);
        if (!smsCaptchaProvider.verify(command)) {
            throw new BadCredentialsException(this.messages
                    .getMessage("UserDetailsAuthenticationProvider.captchaInvalid", "Bad credentials"));
        }


    }

    @Override
    protected AuthUser retrieveUser(String username, Authentication authentication) throws AuthenticationException {
        try {
            AuthUser loadedUser = iamUserDetailsService.loadUserByMobile(((String) authentication.getPrincipal()));
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