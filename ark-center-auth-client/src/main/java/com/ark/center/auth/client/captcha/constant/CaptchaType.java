package com.ark.center.auth.client.captcha.constant;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

@Getter
@Schema(
    enumAsRef = true, 
    description = """
        验证码类型:
         * `SMS` - 短信验证码
         * `EMAIL` - 邮件验证码
         * `IMAGE` - 图片验证码
        """
)
public enum CaptchaType {
    SMS("短信验证码"),
    EMAIL("邮件验证码"),
    IMAGE("图片验证码");

    private final String description;

    CaptchaType(String description) {
        this.description = description;
    }
} 