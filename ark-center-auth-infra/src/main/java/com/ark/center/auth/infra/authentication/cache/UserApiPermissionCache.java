package com.ark.center.auth.infra.authentication.cache;

import cn.hutool.core.thread.NamedThreadFactory;
import com.ark.center.auth.infra.user.gateway.facade.UserPermissionFacade;
import com.ark.component.cache.CacheService;
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
    private List<String> build(Long key) {
        // L2
        Set<Object> objects = l2Cache.setMembers(String.valueOf(key));
        if (CollectionUtils.isNotEmpty(objects)) {
            return objects.stream().map(item -> (String) item).toList();
        }

        // DB

        return objects.stream().map(item -> (String) item).toList();
    }


    public void remove(Long userId) {

    }

    public List<String> get(Long userId) {
        List<String> strings = l1Cache.get(userId);
        System.out.println(l1Cache.stats());
        return strings;
    }

}
