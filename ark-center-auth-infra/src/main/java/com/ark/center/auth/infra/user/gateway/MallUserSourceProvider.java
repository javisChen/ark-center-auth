package com.ark.center.auth.infra.user.gateway;

import com.ark.center.auth.client.application.common.AppCode;
import com.ark.center.auth.infra.user.facade.MemberFacade;
import com.ark.center.member.client.member.MemberQueryApi;
import com.ark.component.lock.LockService;
import com.ark.component.security.base.authentication.AuthUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * 商城会员用户源提供者
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class MallUserSourceProvider implements UserSourceProvider {

    private final MemberGateway memberGateway;
    private final LockService lockService;

    @Override
    public AuthUser retrieveUserByUsername(String username, Authentication authentication) {
        log.info("[用户认证] 开始通过用户名获取用户信息: username={}", username);
        try {
            AuthUser authUser = memberGateway.retrieveUserByUsername(username);
            if (authUser == null) {
                log.info("[用户认证] 用户名未找到对应用户: username={}", username);
                return null;
            }
            log.info("[用户认证] 用户名认证成功: username={}, userId={}", username, authUser.getUserId());
            return authUser;
        } catch (Exception e) {
            log.error("[用户认证] 用户名认证异常: username={}, error={}", username, e.getMessage(), e);
            throw e;
        }
    }

    /**
     * 根据手机号获取或创建用户信息
     * 使用分布式锁确保同一手机号不会被重复注册
     * 
     * @param mobile 手机号
     * @param authentication 认证信息
     * @return 认证用户信息
     */
    @Override
    public AuthUser retrieveUserByMobile(String mobile, Authentication authentication) {
        log.info("[用户认证] 开始处理手机号登录请求: mobile={}", mobile);
        
        try {
            // 1. 通过手机号查询用户信息
            AuthUser authUser = memberGateway.retrieveUserByMobile(mobile);
            
            // 2. 如果用户已存在，直接返回
            if (authUser != null) {
                log.info("[用户认证] 手机号用户登录成功: mobile={}, userId={}, username={}", 
                        mobile, authUser.getUserId(), authUser.getUsername());
                return authUser;
            }
            
            // 3. 用户不存在，使用分布式锁确保并发安全
            String lockKey = "mobile_register_lock:" + mobile;
            
            // 使用带回调的锁API，简化锁的获取和释放逻辑
            AuthUser result = lockService.tryLock(lockKey, 2, 10, TimeUnit.SECONDS, () -> {
                // 获取锁成功后，再次检查用户是否存在（双重检查锁定模式）
                AuthUser lockedAuthUser = memberGateway.retrieveUserByMobile(mobile);
                if (lockedAuthUser != null) {
                    log.info("[用户认证] 获取锁后再次检查发现用户已存在: mobile={}, userId={}", 
                            mobile, lockedAuthUser.getUserId());
                    return lockedAuthUser;
                }
                
                // 确认用户不存在，执行注册流程
                log.info("[用户认证] 手机号用户不存在，开始注册流程: mobile={}", mobile);
                AuthUser newUser = memberGateway.register(mobile);
                log.info("[用户认证] 新用户注册成功并完成登录: mobile={}, userId={}, username={}", 
                        mobile, newUser.getUserId(), newUser.getUsername());
                return newUser;
            });
            
            // 如果获取锁成功并执行了回调，直接返回结果
            if (result != null) {
                return result;
            }
            
            // 获取锁失败，再次尝试查询用户（可能已被其他线程注册）
            log.warn("[用户认证] 获取手机号注册锁失败，可能存在并发注册: mobile={}", mobile);
            authUser = memberGateway.retrieveUserByMobile(mobile);
            if (authUser != null) {
                log.info("[用户认证] 并发情况下，用户已被其他请求注册: mobile={}, userId={}", 
                        mobile, authUser.getUserId());
                return authUser;
            }
            
            // 如果仍然为空，说明出现了异常情况
            log.error("[用户认证] 并发注册处理异常: mobile={}", mobile);
            throw new RuntimeException("手机号注册过程中出现并发问题，请重试");
            
        } catch (Exception e) {
            log.error("[用户认证] 手机号登录/注册过程发生异常: mobile={}, error={}", mobile, e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public Set<AppCode> getSupportedAppCodes() {
        // 支持商城相关的应用
        return Set.of(
            AppCode.MALL_APP
        );
    }
} 