package com.ark.center.auth.infra.user.gateway;

import com.ark.center.auth.client.application.common.AppCode;
import com.ark.center.auth.infra.user.facade.MemberFacade;
import com.ark.center.member.client.member.MemberQueryApi;
import com.ark.component.security.base.authentication.AuthUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * 商城会员用户源提供者
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class MallUserSourceProvider implements UserSourceProvider {

    private final MemberGateway memberGateway;

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
            
            // 2. 如果用户不存在，则进行注册
            if (authUser == null) {
                log.info("[用户认证] 手机号用户不存在，开始注册流程: mobile={}", mobile);
                authUser = memberGateway.register(mobile);
                log.info("[用户认证] 新用户注册成功并完成登录: mobile={}, userId={}, username={}", 
                        mobile, authUser.getUserId(), authUser.getUsername());
                return authUser;
            }
            
            // 3. 返回用户信息
            log.info("[用户认证] 手机号用户登录成功: mobile={}, userId={}, username={}", 
                    mobile, authUser.getUserId(), authUser.getUsername());
            return authUser;
            
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