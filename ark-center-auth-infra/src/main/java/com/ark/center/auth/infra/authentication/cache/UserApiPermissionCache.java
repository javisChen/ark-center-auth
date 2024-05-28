package com.ark.center.auth.infra.authentication.cache;

import cn.hutool.core.thread.NamedThreadFactory;
import com.alibaba.fastjson2.JSON;
import com.ark.center.auth.domain.user.AuthUserApiPermission;
import com.ark.center.auth.infra.user.converter.UserConverter;
import com.ark.center.auth.infra.user.facade.UserPermissionFacade;
import com.ark.center.iam.client.user.dto.UserApiPermissionDTO;
import com.ark.component.cache.CacheService;
import com.ark.component.microservice.rpc.util.RpcUtils;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserApiPermissionCache implements InitializingBean {

    private final CacheService l2Cache;
    private LoadingCache<Long, List<AuthUserApiPermission>> l1Cache;

    private final UserPermissionFacade userPermissionFacade;

    private final UserConverter userConverter;

    private final static String USER_API_PERM_KEY = "role:%s:perm:apis";

    @Override
    public void afterPropertiesSet() throws Exception {
        initL1Cache();
    }

    private void initL1Cache() {
        ExecutorService executorService = Executors.newFixedThreadPool(10,
                new NamedThreadFactory("uap-cache", false));
        l1Cache = Caffeine
                .newBuilder()
                .recordStats()
                .executor(executorService)
                // 1个小时没有访问就删除
                .expireAfterAccess(1, TimeUnit.MINUTES)
                // 最大容量，超过会自动清理空间
                .maximumSize(1024)
                .removalListener((key, value, cause) -> {
                    log.info("用户Api权限本地缓存已失效 key = {} cause = {}", key, cause.name());
                })
                .build(this::build);
    }

    @NotNull
    private List<AuthUserApiPermission> build(Long userId) {
        // L2
        String l2CacheKey = cacheKey(userId);
        String cache = l2Cache.get(l2CacheKey, String.class);
        if (StringUtils.isNotBlank(cache)) {
            // todo 二级缓存续期
            return JSON.parseArray(cache, AuthUserApiPermission.class);
        }
        // DB
        List<UserApiPermissionDTO> apiList = RpcUtils.checkAndGetData(userPermissionFacade.getApiPermissions(userId));
        List<AuthUserApiPermission> userApiPermissions = userConverter.toAuthUserApiPermission(apiList);
        l2Cache.set(l2CacheKey, JSON.toJSONString(userApiPermissions), 12L, TimeUnit.HOURS);
        return userApiPermissions;
    }


    public void remove(Long userId) {
        l1Cache.invalidate(userId);
        l2Cache.del(cacheKey(userId));
    }

    public List<AuthUserApiPermission> get(Long userId) {
        return l1Cache.get(userId);
    }

    private String cacheKey(Long userId) {
        return String.format(USER_API_PERM_KEY, userId);
    }

    public void refresh(Long userId) {
        remove(userId);
        List<AuthUserApiPermission> permissions = get(userId);
        log.info("用户id [{}] Api权限刷新成功: {} \n", userId, permissions);
    }
}
