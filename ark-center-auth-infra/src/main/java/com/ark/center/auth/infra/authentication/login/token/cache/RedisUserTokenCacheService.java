package com.ark.center.auth.infra.authentication.login.token.cache;

import com.ark.center.iam.infra.security.core.token.generate.UserTokenGenerator;
import com.ark.component.cache.CacheService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.stereotype.Component;

/**
 * RedisToken管理器
 */
@Slf4j
@Component
public class RedisUserTokenCacheService extends AbstractUserTokenCacheService {

    private final CacheService cacheService;

    public RedisUserTokenCacheService(UserTokenGenerator userTokenGenerator, CacheService cacheService) {
        super(userTokenGenerator);
        this.cacheService = cacheService;
    }


    @Override
    void saveCache(String key, Object value, long expires) {
        cacheService.set(key, value, expires);
    }

    @Override
    Object getCache(String key) {
        return cacheService.get(key);
    }

    @Override
    void removeCache(String key) {
        cacheService.remove(key);
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        return null;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {

    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return false;
    }
}
