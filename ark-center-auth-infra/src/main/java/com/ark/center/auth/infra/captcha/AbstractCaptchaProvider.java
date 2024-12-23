package com.ark.center.auth.infra.captcha;

import com.ark.center.auth.client.captcha.constant.CaptchaScene;
import com.ark.center.auth.client.captcha.constant.CaptchaType;
import com.ark.center.auth.client.captcha.command.GenerateCaptchaCommand;
import com.ark.center.auth.client.captcha.command.VerifyCaptchaCommand;
import com.ark.center.auth.client.captcha.dto.CaptchaContentDTO;
import com.ark.component.cache.CacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
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
    protected String codePrefix = "cap:";  // 缓存key前缀

    private static final int CLEAR_CAPTCHA_FAIL_COUNT = 3;  // 清除验证码的失败次数
    
    @Override
    public CaptchaContentDTO generate(GenerateCaptchaCommand command) {
        CaptchaType type = getProviderType();
        String target = command.getTarget();
        CaptchaScene scene = command.getScene();
        
        log.info("[Captcha Generate] Start generating captcha, type={}, target={}, scene={}", 
                type, target, scene);

        String cacheKey = buildCaptchaKey(target, scene);
        CaptchaContentDTO existingResult = null;
        try {
            existingResult = getCachedCaptcha(cacheKey);
        } catch (Exception e) {
            log.error("[Captcha Generate] Fail to get cached result", e);
        }

        if (existingResult != null) {
            log.info("[Captcha Generate] Existing captcha found, type={}, target={}, scene={}", 
                    type, target, scene);
            return existingResult;
        }

        String code = generateCode();
        CaptchaContentDTO result = buildResult(code);

        boolean saved = saveWithLock(cacheKey, result);
        if (!saved) {
            log.info("[Captcha Generate] Concurrent generation detected, type={}, target={}, scene={}", 
                    type, target, scene);
            return getCachedCaptcha(cacheKey);
        }

        try {
            send(target, code);
            log.info("[Captcha Generate] Captcha sent successfully, type={}, target={}, scene={}", 
                    type, target, scene);
        } catch (Exception e) {
            cacheService.del(cacheKey);
            log.error("[Captcha Generate] Failed to send captcha, type={}, target={}, scene={}", 
                    type, target, scene, e);
        }
        
        return result;

    }

    @Override
    public boolean verify(VerifyCaptchaCommand command) {
        CaptchaType type = getProviderType();
        String target = command.getTarget();
        CaptchaScene scene = command.getScene();
        
        log.info("[Captcha Verify] Start verifying captcha, type={}, target={}, scene={}", 
                type, target, scene);

        // 1. 获取并校验验证码
        String captchaCacheKey = buildCaptchaKey(target, scene);
        CaptchaContentDTO savedResult = getCachedCaptcha(captchaCacheKey);
        
        if (savedResult == null) {
            log.warn("[Captcha Verify] Captcha not found or expired, type={}, target={}, scene={}", 
                    type, target, scene);
            return false;
        }

        // 2. 验证码匹配检查
        boolean verified = savedResult.getCode().equals(command.getCode());
        if (verified) {
            // 验证成功：删除验证码和失败计数
            cacheService.del(captchaCacheKey);
            cacheService.del(buildFailCountKey(target, scene));
            log.info("[Captcha Verify] Captcha verified successfully, type={}, target={}, scene={}", 
                    type, target, scene);
        } else {
            // 验证失败：增加失败计数
            String failCountKey = buildFailCountKey(target, scene);
            long newFailCount = cacheService.incrBy(failCountKey, 1L);
            
            // 失败3次后清除验证码和失败计数
            if (newFailCount >= CLEAR_CAPTCHA_FAIL_COUNT) {
                cacheService.del(captchaCacheKey);
                cacheService.del(failCountKey);
                log.warn("[Captcha Verify] Clear captcha and fail count after {} failures, type={}, target={}, scene={}", 
                        CLEAR_CAPTCHA_FAIL_COUNT, type, target, scene);
            }
            
            log.warn("[Captcha Verify] Captcha verification failed, count={}, type={}, target={}, scene={}", 
                    newFailCount, type, target, scene);
        }

        return verified;
    }

    private CaptchaContentDTO buildResult(String code) {
        long expireAt = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(expireMinutes);
        return CaptchaContentDTO.builder()
                .code(code)
                .expireAt(expireAt)
                .expireTime(LocalDateTime.ofInstant(
                    Instant.ofEpochMilli(expireAt), 
                    ZoneId.systemDefault()
                ))
                .build();
    }

    private boolean saveWithLock(String key, CaptchaContentDTO result) {
        return cacheService.setIfAbsent(key, result, expireMinutes, TimeUnit.MINUTES);
    }

    private CaptchaContentDTO getCachedCaptcha(String key) {
        return cacheService.get(key, CaptchaContentDTO.class);
    }

    private String buildCaptchaKey(String target, CaptchaScene scene) {
        return String.format("%s%s:%s:%s", 
            codePrefix,
            getProviderType().name().toLowerCase(),
            scene.name().toLowerCase(), 
            target
        );
    }

    private String buildFailCountKey(String target, CaptchaScene scene) {
        return String.format("%s%s:%s:f:%s",
            codePrefix,
            getProviderType().name().toLowerCase(),
            scene.name().toLowerCase(),
            target
        );
    }

    protected abstract String generateCode();

    @Override
    public abstract CaptchaType getProviderType();

    @Override
    public void send(String target, String code) {
        // 默认空实现，由子类覆盖实现具体的发送逻辑
    }
}