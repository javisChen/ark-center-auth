package com.ark.center.auth.client.application.common;

import com.ark.center.auth.client.authentication.common.AppType;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

/**
 * 应用系统编码
 */
@Getter
@Schema(
    enumAsRef = true,
    description = """
        应用系统编码:
         * `MALL_APP` - 商城APP
         * `MALL_H5` - 商城H5
         * `OPERATION_ADMIN` - 运营管理后台
         * `PLATFORM_ADMIN` - 平台管理后台
        """
)
public enum AppCode {

    MALL_APP("商城APP", AppType.CONSUMER),
    MALL_H5("商城H5", AppType.CONSUMER),
    OPERATION_ADMIN("运营管理后台", AppType.OPERATION),
    PLATFORM_ADMIN("平台管理后台", AppType.PLATFORM);

    private final String description;
    private final AppType appType;

    AppCode(String description, AppType appType) {
        this.description = description;
        this.appType = appType;
    }
} 