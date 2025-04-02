package com.ark.center.auth.infra.verifycode;

import com.ark.center.auth.client.verifycode.common.VerifyCodeScene;
import com.ark.center.auth.client.verifycode.common.VerifyCodeType;
import com.ark.center.auth.client.verifycode.command.GenerateVerifyCodeCommand;
import com.ark.center.auth.client.verifycode.command.VerifyCodeCommand;
import com.ark.center.auth.client.verifycode.dto.VerifyCodeDTO;
import com.ark.component.cache.CacheService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * 验证码提供者抽象实现
 */
@Slf4j
@RequiredArgsConstructor
public abstract class AbstractVerifyCodeProvider implements VerifyCodeProvider {

    protected final CacheService cacheService;

    // 子类可以覆盖这些默认配置
    protected int codeLength = 6;        // 验证码长度
    protected long expireMinutes = 2;    // 过期时间(分钟)
    private final static String CODE_PREFIX = "verify:code:";  // 缓存key前缀

    private static final int CLEAR_VERIFY_CODE_FAIL_COUNT = 3;  // 清除验证码的失败次数

    @Data
    static class VerifyCodeCacheItem {
        private String code;
        private String target;
        private VerifyCodeScene scene;
        private VerifyCodeType type;
        private Long createTime;
    }

    @Override
    public VerifyCodeDTO generate(GenerateVerifyCodeCommand command) {

        VerifyCodeType type = getProviderType();
        String target = command.getTarget();
        VerifyCodeScene scene = command.getScene();

        log.info("[VerifyCode Generate] Start generating verify code, type={}, target={}, scene={}",
                type, target, scene);

        // 生成验证码ID
        String verifyCodeId = generateVerifyCodeId();
        String code = generateCode();

        // 构建缓存项
        VerifyCodeCacheItem cacheItem = new VerifyCodeCacheItem();
        cacheItem.setCode(code);
        cacheItem.setTarget(target);
        cacheItem.setScene(scene);
        cacheItem.setType(type);
        cacheItem.setCreateTime(System.currentTimeMillis());

        // 保存验证码
        String cacheKey = buildVerifyCodeKey(verifyCodeId);
        boolean saved = saveWithLock(cacheKey, cacheItem);
        if (!saved) {
            log.warn("[VerifyCode Generate] Failed to save verify code, type={}, target={}, scene={}",
                    type, target, scene);
            throw new IllegalStateException("Failed to save verify code");
        }

        try {
            send(target, code);
            log.info("[VerifyCode Generate] Verify code sent successfully, type={}, target={}, scene={}",
                    type, target, scene);
        } catch (Exception e) {
            cacheService.del(cacheKey);
            log.error("[VerifyCode Generate] Failed to send verify code, type={}, target={}, scene={}",
                    type, target, scene, e);
            throw e;
        }

        // 构建返回结果（不包含验证码）
        VerifyCodeDTO result = new VerifyCodeDTO();
        result.setVerifyCodeId(verifyCodeId);
        // result.setCode(code);
        return result;
    }

    @Override
    public boolean verify(VerifyCodeCommand command) {
        VerifyCodeType type = getProviderType();
        String target = command.getTarget();
        VerifyCodeScene scene = command.getScene();
        String verifyCodeId = command.getVerifyCodeId();

        log.info("[VerifyCode Verify] Start verifying code, type={}, target={}, scene={}, verifyCodeId={}",
                type, target, scene, verifyCodeId);

        String verifyCodeCacheKey = buildVerifyCodeKey(verifyCodeId);
        VerifyCodeCacheItem cacheItem = getCachedVerifyCode(verifyCodeCacheKey);

        // 验证码基础校验
        if (!validateBasicVerifyCode(cacheItem, type, target, scene, verifyCodeId)) {
            return false;
        }

        // 验证码匹配检查
        boolean verified = StringUtils.equals(cacheItem.getCode(), command.getCode());
        handleVerificationResult(verified, verifyCodeCacheKey, type, target, scene, verifyCodeId);
        return verified;
    }

    private boolean validateBasicVerifyCode(VerifyCodeCacheItem cacheItem,
                                            VerifyCodeType type,
                                            String target,
                                            VerifyCodeScene scene,
                                            String verifyCodeId) {
        // 1. 验证码是否存在
        if (cacheItem == null) {
            log.warn("[VerifyCode Verify] Verify code not found or expired, type={}, target={}, scene={}, verifyCodeId={}",
                    type, target, scene, verifyCodeId);
            return false;
        }

        // 2. 验证接收者信息
        if (!StringUtils.equals(cacheItem.getTarget(), target)) {
            log.warn("[VerifyCode Verify] Target mismatch, expected={}, actual={}, type={}, scene={}, verifyCodeId={}",
                    cacheItem.getTarget(), target, type, scene, verifyCodeId);
            return false;
        }

        // 3. 验证场景
        if (cacheItem.getScene() != scene) {
            log.warn("[VerifyCode Verify] Scene mismatch, expected={}, actual={}, type={}, target={}, verifyCodeId={}",
                    cacheItem.getScene(), scene, type, target, verifyCodeId);
            return false;
        }

        // 4. 验证类型
        if (cacheItem.getType() != type) {
            log.warn("[VerifyCode Verify] Type mismatch, expected={}, actual={}, target={}, scene={}, verifyCodeId={}",
                    cacheItem.getType(), type, target, scene, verifyCodeId);
            return false;
        }

        return true;
    }

    private void handleVerificationResult(boolean verified,
                                          String verifyCodeCacheKey,
                                          VerifyCodeType type,
                                          String target,
                                          VerifyCodeScene scene,
                                          String verifyCodeId) {
        if (verified) {
            // 验证成功：删除验证码和失败计数
            cacheService.del(verifyCodeCacheKey);
            String failCountKey = buildFailCountKey(verifyCodeId);
            cacheService.del(failCountKey);
            log.info("[VerifyCode Verify] Verify code verified successfully, type={}, target={}, scene={}, verifyCodeId={}",
                    type, target, scene, verifyCodeId);
        } else {
            // 验证失败：增加失败计数
            String failCountKey = buildFailCountKey(verifyCodeId);
            long newFailCount = cacheService.incrBy(failCountKey, 1L);
            // 失败计数的过期时间与验证码相同
            cacheService.setIfAbsent(failCountKey, newFailCount, expireMinutes, TimeUnit.MINUTES);

            // 失败3次后清除验证码
            if (newFailCount >= CLEAR_VERIFY_CODE_FAIL_COUNT) {
                cacheService.del(verifyCodeCacheKey);
                cacheService.del(failCountKey);
                log.warn("[VerifyCode Verify] Clear verify code after {} failures, type={}, target={}, scene={}, verifyCodeId={}",
                        CLEAR_VERIFY_CODE_FAIL_COUNT, type, target, scene, verifyCodeId);
            }

            log.warn("[VerifyCode Verify] Verify code verification failed, count={}, type={}, target={}, scene={}, verifyCodeId={}",
                    newFailCount, type, target, scene, verifyCodeId);
        }
    }

    private boolean saveWithLock(String key, VerifyCodeCacheItem cacheItem) {
        return cacheService.setIfAbsent(key, cacheItem, expireMinutes, TimeUnit.MINUTES);
    }

    private VerifyCodeCacheItem getCachedVerifyCode(String key) {
        return cacheService.get(key, VerifyCodeCacheItem.class);
    }

    private String buildVerifyCodeKey(String verifyCodeId) {
        return String.format("%s%s", CODE_PREFIX, verifyCodeId);
    }

    private String buildFailCountKey(String verifyCodeId) {
        return String.format("%s%s:f", CODE_PREFIX, verifyCodeId);
    }

    protected String generateVerifyCodeId() {
        return String.format("%s_%s_%d",
                getProviderType().name().toLowerCase(),
                UUID.randomUUID().toString().replace("-", "").substring(0, 8),
                Instant.now().toEpochMilli()
        );
    }

    protected abstract String generateCode();

    @Override
    public abstract VerifyCodeType getProviderType();

    @Override
    public void send(String target, String code) {
        // 默认空实现，由子类覆盖实现具体的发送逻辑
    }
}