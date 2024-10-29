package com.ark.center.auth.infra.authentication.login.code;

import cn.hutool.core.util.RandomUtil;
import com.ark.center.auth.infra.authentication.common.ResponseUtils;
import com.ark.center.auth.infra.authentication.common.Uris;
import com.ark.center.auth.infra.cache.AuthCacheKey;
import com.ark.component.cache.CacheService;
import com.ark.component.dto.ServerResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Slf4j
public class SendSmsCodeFilter extends OncePerRequestFilter {

    private final SendSmsCodeConverter sendSmsCodeConverter = new SendSmsCodeConverter();

    private final CacheService cacheService;

    private final RequestMatcher requiresAuthenticationRequestMatcher =
            new AntPathRequestMatcher(Uris.SMS_CODE, HttpMethod.POST.name());

    public SendSmsCodeFilter(CacheService cacheService) {
        this.cacheService = cacheService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!requiresAuthentication(request, response, filterChain)) {
            filterChain.doFilter(request, response);
            return;
        }

        SendSmsCodeRequest sendSmsCodeRequest = sendSmsCodeConverter.readFromRequest(request);
        String mobile = sendSmsCodeRequest.getMobile();
        if (StringUtils.isBlank(mobile)) {
            return;
        }
        // todo 暂时是mock随机数打印出来，实际上要开发消息服务进行发送短信
        try {
            String code = RandomUtil.randomNumbers(6);
            log.info("Sms code is generated -> [{}]", code);
            String codeCacheKey = String.format(AuthCacheKey.CACHE_KEY_USER_MOBILE_LOGIN_CODE, mobile);

            // 删除原本存在的验证码
            cacheService.del(codeCacheKey);

            // 保存新的验证码
            cacheService.set(codeCacheKey, code, 2L, TimeUnit.MINUTES);

        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }

        ResponseUtils.writeOk(ServerResponse.ok(), response);

    }

    private boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
        return this.requiresAuthenticationRequestMatcher.matches(request);
    }

}
