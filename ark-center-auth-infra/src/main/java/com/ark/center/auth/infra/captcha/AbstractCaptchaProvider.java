package com.ark.center.auth.infra.captcha;

import com.ark.center.auth.client.captcha.CaptchaResult;
import com.ark.center.auth.client.captcha.CaptchaScene;
import com.ark.center.auth.client.captcha.CaptchaType;
import com.ark.center.auth.client.captcha.dto.GenerateCaptchaCommand;
import com.ark.center.auth.client.captcha.dto.VerifyCaptchaCommand;
import com.ark.component.cache.CacheService;
import com.ark.component.exception.ExceptionFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.TimeUnit;

/**
 * 验证码提供者抽象实现
 */
@Slf4j
@RequiredArgsConstructor
public abstract class AbstractCaptchaProvider implements CaptchaProvider {

    protected final CacheService cacheService;

    // 子类可以覆盖这些默认配置
    protected int codeLength = 6;        // 验证码长度
    protected long expireMinutes = 2;    // 过期时间(分钟)
    protected String codePrefix = "captcha:";  // 缓存key前缀

    @Override
    public CaptchaResult generate(GenerateCaptchaCommand command) {
        CaptchaType type = getProviderType();
        String target = command.getTarget();
        CaptchaScene scene = command.getScene();
        
        log.info("[Captcha Generate] Start generating captcha, type={}, target={}, scene={}", 
                type, target, scene);

        String cacheKey = buildCacheKey(target, scene);
        CaptchaResult existingResult = getCachedResult(cacheKey);
        
        if (existingResult != null) {
            log.info("[Captcha Generate] Existing captcha found, type={}, target={}, scene={}", 
                    type, target, scene);
            return existingResult;
        }

        String code = generateCode();
        CaptchaResult result = buildResult(code);

        boolean saved = saveWithLock(cacheKey, result);
        if (!saved) {
            log.info("[Captcha Generate] Concurrent generation detected, type={}, target={}, scene={}", 
                    type, target, scene);
            return getCachedResult(cacheKey);
        }

        try {
            send(target, code);
            log.info("[Captcha Generate] Captcha sent successfully, type={}, target={}, scene={}", 
                    type, target, scene);
            return result;
        } catch (Exception e) {
            cacheService.del(cacheKey);
            log.error("[Captcha Generate] Failed to send captcha, type={}, target={}, scene={}", 
                    type, target, scene, e);
            throw ExceptionFactory.userException("Failed to send captcha");
        }
    }

    @Override
    public boolean verify(VerifyCaptchaCommand command) {
        CaptchaType type = getProviderType();
        String target = command.getTarget();
        CaptchaScene scene = command.getScene();
        
        log.info("[Captcha Verify] Start verifying captcha, type={}, target={}, scene={}", 
                type, target, scene);

        String cacheKey = buildCacheKey(target, scene);
        CaptchaResult savedResult = getCachedResult(cacheKey);
        
        if (savedResult == null) {
            log.warn("[Captcha Verify] Captcha not found or expired, type={}, target={}, scene={}", 
                    type, target, scene);
            return false;
        }

        boolean verified = savedResult.getCode().equals(command.getCode());
        if (verified) {
            cacheService.del(cacheKey);
            log.info("[Captcha Verify] Captcha verified successfully, type={}, target={}, scene={}", 
                    type, target, scene);
        } else {
            log.warn("[Captcha Verify] Captcha verification failed, type={}, target={}, scene={}", 
                    type, target, scene);
        }

        return verified;
    }

    private CaptchaResult buildResult(String code) {
        return CaptchaResult.builder()
                .code(code)
                .expireTime(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(expireMinutes))
                .success(true)
                .build();
    }

    private boolean saveWithLock(String key, CaptchaResult result) {
        return cacheService.setIfAbsent(key, result, expireMinutes, TimeUnit.MINUTES);
    }

    private CaptchaResult getCachedResult(String key) {
        return cacheService.get(key, CaptchaResult.class);
    }

    private String buildCacheKey(String target, CaptchaScene scene) {
        return String.format("%s%s:%s:%s", codePrefix, getProviderType().name(), scene.name(), target).toLowerCase();
    }

    protected abstract String generateCode();

    @Override
    public abstract CaptchaType getProviderType();

    @Override
    public void send(String target, String code) {
        // 默认空实现，由子类覆盖实现具体的发送逻辑
    }
}