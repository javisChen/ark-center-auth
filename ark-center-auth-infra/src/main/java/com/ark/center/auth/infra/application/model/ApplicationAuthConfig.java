package com.ark.center.auth.infra.application.model;

import com.ark.center.auth.client.application.common.AppCode;
import com.ark.center.auth.client.authentication.common.AuthStrategy;
import com.ark.center.auth.client.authentication.common.AppType;
import lombok.Builder;
import lombok.Data;

import java.util.Set;

/**
 * 应用系统认证配置
 */
@Data
@Builder
public class ApplicationAuthConfig {

    /**
     * 应用名称
     */
    private String name;

    /**
     * 应用编码
     */
    private AppCode code;

    /**
     * 应用类型
     */
    private AppType appType;

    /**
     * 允许的认证策略
     */
    private Set<AuthStrategy> allowedAuthStrategies;
} 