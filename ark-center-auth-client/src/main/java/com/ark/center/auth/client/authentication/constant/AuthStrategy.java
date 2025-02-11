package com.ark.center.auth.client.authentication.constant;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

/**
 * 认证策略枚举
 */
@Getter
@Schema(
    enumAsRef = true,
    description = """
        认证策略:
         * `PWD` - 密码认证
         * `SMS` - 短信认证
         * `EMAIL` - 邮箱认证
         * `WECHAT` - 微信认证
         * `OAUTH` - OAuth认证
        """
)
public enum AuthStrategy {

    PWD("密码认证"),
    SMS("短信认证"),
    EMAIL("邮箱认证"),
    WECHAT("微信认证"),
    OAUTH("OAuth认证");

    private final String description;

    AuthStrategy(String description) {
        this.description = description;
    }
} 