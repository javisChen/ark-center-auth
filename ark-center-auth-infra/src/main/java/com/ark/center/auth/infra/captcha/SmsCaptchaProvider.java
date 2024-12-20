package com.ark.center.auth.infra.captcha;

import cn.hutool.core.util.RandomUtil;

import com.ark.center.auth.client.captcha.CaptchaType;
import com.ark.component.cache.CacheService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class SmsCaptchaProvider extends AbstractCaptchaProvider {

    public SmsCaptchaProvider(CacheService cacheService) {
        super(cacheService);
    }

    @Override
    public CaptchaType getProviderType() {
        return CaptchaType.SMS;
    }

    @Override
    protected String generateCode() {
        return RandomUtil.randomNumbers(this.codeLength);
    }

    @Override
    public void send(String target, String code) {
        // TODO: 实现具体的短信发送逻辑
        log.info("Sending SMS code {} to phone {}", code, target);
        // 这里需要集成具体的短信服务商SDK
        // 比如阿里云短信、腾讯云短信等
    }
    
} 