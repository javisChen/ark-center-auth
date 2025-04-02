package com.ark.center.auth.infra.verifycode;

import com.ark.center.auth.client.verifycode.common.VerifyCodeType;
import com.ark.center.auth.client.verifycode.command.GenerateVerifyCodeCommand;
import com.ark.center.auth.client.verifycode.command.VerifyCodeCommand;
import com.ark.center.auth.client.verifycode.dto.VerifyCodeDTO;

/**
 * 验证码提供者接口
 */
public interface VerifyCodeProvider {
    /**
     * 获取验证码提供者类型
     *
     * @return 验证码类型
     */
    VerifyCodeType getProviderType();
    
    /**
     * 创建验证码
     *
     * @param command 创建验证码命令
     * @return 验证码结果
     */
    VerifyCodeDTO generate(GenerateVerifyCodeCommand command);
    
    /**
     * 验证验证码
     *
     * @param command 验证验证码命令
     * @return 验证结果
     */
    boolean verify(VerifyCodeCommand command);
    
    /**
     * 发送验证码
     *
     * @param target 目标对象(手机号/邮箱)
     * @param code 验证码
     */
    void send(String target, String code);
}