package com.ark.center.auth.client.captcha;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "验证码场景")
public enum CaptchaScene {
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
    
    @Schema(description = "默认场景")
    DEFAULT("默认场景");

    private final String description;

    CaptchaScene(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
} 