package com.ark.center.auth.client.verifycode.common;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

@Getter
@Schema(
    enumAsRef = true, 
    description = """
        验证码场景:
         * `LOGIN` - 登录验证
         * `REGISTER` - 注册验证
         * `RESET_PASSWORD` - 重置密码
         * `BIND_PHONE` - 绑定手机
         * `UNBIND_PHONE` - 解绑手机
         * `DEFAULT` - 默认场景
        """
)
public enum VerifyCodeScene {
    LOGIN("登录验证"),
    REGISTER("注册验证"),
    RESET_PASSWORD("重置密码"),
    BIND_PHONE("绑定手机"),
    UNBIND_PHONE("解绑手机"),
    DEFAULT("默认场景");

    private final String description;

    VerifyCodeScene(String description) {
        this.description = description;
    }
} 