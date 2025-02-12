package com.ark.center.auth.infra.application.repository;

import com.ark.center.auth.client.application.common.AppCode;
import com.ark.center.auth.infra.application.model.ApplicationAuthConfig;

/**
 * 应用系统认证配置仓储接口
 */
public interface ApplicationAuthConfigRepository {

    /**
     * 根据应用编码获取配置
     *
     * @param appCode 应用编码
     * @return 配置信息
     */
    ApplicationAuthConfig findByCode(AppCode appCode);

} 