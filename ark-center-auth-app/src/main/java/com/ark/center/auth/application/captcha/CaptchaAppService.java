package com.ark.center.auth.application.captcha;

import com.ark.center.auth.client.captcha.constant.CaptchaType;
import com.ark.center.auth.client.captcha.command.GenerateCaptchaCommand;
import com.ark.center.auth.client.captcha.command.VerifyCaptchaCommand;
import com.ark.center.auth.client.captcha.dto.CaptchaContentDTO;
import com.ark.center.auth.infra.captcha.CaptchaProvider;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 验证码应用服务
 */
@Service
public class CaptchaAppService {
    
    private final Map<CaptchaType, CaptchaProvider> providerMap;

    public CaptchaAppService(List<CaptchaProvider> providers) {
        this.providerMap = providers.stream()
                .collect(Collectors.toMap(
                        CaptchaProvider::getProviderType,
                        Function.identity()
                ));
    }
    
    /**
     * 创建验证码
     *
     * @param command 创建验证码命令
     * @return 验证码结果
     */
    public CaptchaContentDTO create(GenerateCaptchaCommand command) {
        return getProvider(command.getType()).generate(command);
    }
    
    /**
     * 验证验证码
     *
     * @param command 验证验证码命令
     * @return 验证结果
     */
    public boolean verify(VerifyCaptchaCommand command) {
        return getProvider(command.getType()).verify(command);
    }
    
    /**
     * 获取验证码提供者
     */
    private CaptchaProvider getProvider(CaptchaType type) {
        CaptchaProvider provider = providerMap.get(type);
        if (provider == null) {
            throw new IllegalArgumentException("Unsupported captcha type: " + type);
        }
        return provider;
    }
}