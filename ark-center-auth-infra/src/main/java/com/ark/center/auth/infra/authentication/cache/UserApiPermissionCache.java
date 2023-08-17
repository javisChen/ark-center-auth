package com.ark.center.auth.infra.authentication.cache;

import cn.hutool.core.thread.NamedThreadFactory;
import com.ark.center.auth.infra.user.gateway.facade.UserPermissionFacade;
import com.ark.center.iam.client.user.dto.UserApiPermissionDTO;
import com.ark.component.cache.CacheService;
import com.ark.component.microservice.rpc.util.RpcUtils;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserApiPermissionCache implements InitializingBean {

    private final CacheService l2Cache;
    private LoadingCache<Long, List<String>> l1Cache;

    private final UserPermissionFacade userPermissionFacade;

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
                .expireAfterAccess(1, TimeUnit.HOURS)
                // 最大容量，超过会自动清理空间
                .maximumSize(1024)
                .removalListener((key, value, cause) -> {
                    log.info("用户Api权限本地缓存已失效 key = {} cause = {}", key, cause.name());
                })
                .build(this::build);
    }

    @NotNull
    private List<String> build(Long userId) {

        // L2
        String l2CacheKey = cacheKey(userId);
        Set<Object> objects = l2Cache.setMembers(l2CacheKey);
        if (CollectionUtils.isNotEmpty(objects)) {
            return objects.stream().map(item -> (String) item).toList();
        }

        // DB
        List<UserApiPermissionDTO> apiList = RpcUtils.checkAndGetData(userPermissionFacade.getApiPermissions(userId));
        List<String> result = apiList.stream().map(api -> api.getUri() + ":" + api.getMethod()).toList();

        l2Cache.setAdd(l2CacheKey, result.toArray());
        return result;
    }


    public void remove(Long userId) {
        l1Cache.invalidate(userId);
        l2Cache.remove(cacheKey(userId));
    }

    public List<String> get(Long userId) {
        List<String> strings = l1Cache.get(userId);
        System.out.println(l1Cache.stats());
        return strings;
    }

    private String cacheKey(Long userId) {
        return String.format(USER_API_PERM_KEY, userId);
    }

}
