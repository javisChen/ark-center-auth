package com.ark.center.auth.client.captcha;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "验证码类型")
public enum CaptchaType {
    @Schema(description = "短信验证码")
    SMS,
    @Schema(description = "邮件验证码")
    EMAIL,
    @Schema(description = "图片验证码")
    IMAGE
} 