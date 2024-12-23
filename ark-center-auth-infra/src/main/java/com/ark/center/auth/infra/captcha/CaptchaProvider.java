package com.ark.center.auth.infra.captcha;

import com.ark.center.auth.client.captcha.constant.CaptchaType;
import com.ark.center.auth.client.captcha.command.GenerateCaptchaCommand;
import com.ark.center.auth.client.captcha.command.VerifyCaptchaCommand;
import com.ark.center.auth.client.captcha.dto.CaptchaContentDTO;

/**
 * 验证码提供者接口
 */
public interface CaptchaProvider {
    /**
     * 获取验证码提供者类型
     *
     * @return 验证码类型
     */
    CaptchaType getProviderType();
    
    /**
     * 创建验证码
     *
     * @param command 创建验证码命令
     * @return 验证码结果
     */
    CaptchaContentDTO generate(GenerateCaptchaCommand command);
    
    /**
     * 验证验证码
     *
     * @param command 验证验证码命令
     * @return 验证结果
     */
    boolean verify(VerifyCaptchaCommand command);
    
    /**
     * 发送验证码
     *
     * @param target 目标对象(手机号/邮箱)
     * @param code 验证码
     */
    void send(String target, String code);
}