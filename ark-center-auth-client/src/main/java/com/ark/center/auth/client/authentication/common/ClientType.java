package com.ark.center.auth.client.authentication.common;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

/**
 * 客户端类型枚举
 * 用于区分不同的客户端入口
 */
@Getter
@Schema(
    enumAsRef = true,
    description = """
        客户端类型:
         * `IOS` - iOS原生APP
         * `ANDROID` - Android原生APP
         * `WEB` - 桌面端网页
         * `H5` - 移动端网页
         * `WECHAT_MP` - 微信小程序
         * `ALIPAY_MP` - 支付宝小程序
         * `BYTEDANCE_MP` - 抖音小程序
         * `DESKTOP` - 桌面客户端
        """
)
public enum ClientType {

    IOS("iOS原生APP"),
    ANDROID("Android原生APP"),
    WEB("桌面端网页"),
    H5("移动端网页"),
    WECHAT_MP("微信小程序"),
    ALIPAY_MP("支付宝小程序"),
    BYTEDANCE_MP("抖音小程序"),
    DESKTOP("桌面客户端");

    private final String description;

    ClientType(String description) {
        this.description = description;
    }
} 