package com.ark.center.auth.client.verifycode.common;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

@Getter
@Schema(
    enumAsRef = true, 
    description = """
        验证码类型:
         * `SMS` - 短信验证码
         * `EMAIL` - 邮箱验证码
         * `IMAGE` - 图形验证码
        """
)
public enum VerifyCodeType {
    SMS("短信验证码"),
    EMAIL("邮箱验证码"),
    IMAGE("图形验证码");

    private final String description;

    VerifyCodeType(String description) {
        this.description = description;
    }
} 