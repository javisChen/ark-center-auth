package com.ark.center.auth.client.login.constant;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

import java.util.Arrays;

/**
 * 登录认证方式枚举
 */
@Getter
@Schema(
    enumAsRef = true,
    description = """
        登录认证方式:
         * `ACCOUNT` - 账号密码登录
         * `MOBILE` - 手机验证码登录
        """
)
public enum LoginMode {

    ACCOUNT("账号密码登录"),
    MOBILE("手机验证码登录");

    private final String description;

    LoginMode(String description) {
        this.description = description;
    }

    /**
     * 根据编码获取登录方式
     *
     * @param code 登录方式编码
     * @return 登录方式枚举
     */
    public static LoginMode byCode(String code) {
        return Arrays.stream(values())
                .filter(loginMode -> loginMode.name().equals(code.toUpperCase()))
                .findFirst()
                .orElse(null);
    }
}
