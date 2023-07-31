package com.ark.center.auth.infra.authentication.login.token.cache;

import com.ark.center.iam.infra.security.core.token.generate.UserTokenGenerator;
import com.ark.component.cache.CacheService;
import lombok.extern.slf4j.Slf4j;
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

}
