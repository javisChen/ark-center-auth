package com.ark.center.auth.infra.application.service;

import com.ark.center.auth.client.application.common.AppCode;
import com.ark.center.auth.client.authentication.common.AuthStrategy;
import com.ark.center.auth.infra.application.model.ApplicationAuthConfig;
import com.ark.center.auth.infra.application.repository.ApplicationAuthConfigRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * 应用系统认证配置服务
 */
@Service
@RequiredArgsConstructor
public class ApplicationAuthConfigService {

    private final ApplicationAuthConfigRepository applicationAuthConfigRepository;

    /**
     * 获取应用系统认证配置
     *
     * @param appCode 应用编码
     * @return 认证配置
     */
    public ApplicationAuthConfig getConfig(AppCode appCode) {
        return applicationAuthConfigRepository.findByCode(appCode);
    }

    /**
     * 验证认证策略是否允许
     *
     * @param appCode 应用编码
     * @param authStrategy 认证策略
     * @return 是否允许
     */
    public boolean isAuthStrategyAllowed(AppCode appCode, AuthStrategy authStrategy) {
        ApplicationAuthConfig config = getConfig(appCode);
        return config != null && config.getAllowedAuthStrategies().contains(authStrategy);
    }
} 