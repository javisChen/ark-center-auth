package com.ark.center.auth.client.captcha;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "验证码业务类型")
public enum CaptchaBizType {
    @Schema(description = "登录验证")
    LOGIN("登录验证"),
    @Schema(description = "注册验证")
    REGISTER("注册验证"),
    @Schema(description = "重置密码")
    RESET_PASSWORD("重置密码"),
    @Schema(description = "绑定手机")
    BIND_PHONE("绑定手机"),
    @Schema(description = "解绑手机")
    UNBIND_PHONE("解绑手机"),
    @Schema(description = "默认验证")
    DEFAULT("默认验证");

    private final String description;

    CaptchaBizType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
} 