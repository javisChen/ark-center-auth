package com.ark.center.auth.infra.application.repository.impl;

import com.ark.center.auth.client.application.common.AppCode;
import com.ark.center.auth.client.authentication.common.AuthStrategy;
import com.ark.center.auth.client.authentication.common.AppType;
import com.ark.center.auth.infra.application.model.ApplicationAuthConfig;
import com.ark.center.auth.infra.application.repository.ApplicationAuthConfigRepository;
import org.springframework.stereotype.Repository;

import java.util.EnumMap;
import java.util.Map;
import java.util.Set;

/**
 * 应用系统认证配置仓储实现类
 */
@Repository
public class ApplicationAuthConfigRepositoryImpl implements ApplicationAuthConfigRepository {

    private final Map<AppCode, ApplicationAuthConfig> configMap;

    public ApplicationAuthConfigRepositoryImpl() {
        configMap = new EnumMap<>(AppCode.class);
        initializeConfigs();
    }

    private void initializeConfigs() {
        // 商城APP
        configMap.put(AppCode.MALL_APP, ApplicationAuthConfig.builder()
                .name("商城APP")
                .code(AppCode.MALL_APP)
                .appType(AppType.CONSUMER)
                .allowedAuthStrategies(Set.of(AuthStrategy.PWD, AuthStrategy.SMS, AuthStrategy.WECHAT))
                .build());

        // 商城H5
        configMap.put(AppCode.MALL_H5, ApplicationAuthConfig.builder()
                .name("商城H5")
                .code(AppCode.MALL_H5)
                .appType(AppType.CONSUMER)
                .allowedAuthStrategies(Set.of(AuthStrategy.PWD, AuthStrategy.SMS, AuthStrategy.WECHAT))
                .build());

        // 运营管理后台
        configMap.put(AppCode.OPERATION_ADMIN, ApplicationAuthConfig.builder()
                .name("运营管理后台")
                .code(AppCode.OPERATION_ADMIN)
                .appType(AppType.OPERATION)
                .allowedAuthStrategies(Set.of(AuthStrategy.PWD, AuthStrategy.SMS))
                .build());

        // 平台管理后台
        configMap.put(AppCode.PLATFORM_ADMIN, ApplicationAuthConfig.builder()
                .name("平台管理后台")
                .code(AppCode.PLATFORM_ADMIN)
                .appType(AppType.PLATFORM)
                .allowedAuthStrategies(Set.of(AuthStrategy.PWD, AuthStrategy.SMS))
                .build());
    }

    @Override
    public ApplicationAuthConfig findByCode(AppCode appCode) {
        return configMap.get(appCode);
    }
} 