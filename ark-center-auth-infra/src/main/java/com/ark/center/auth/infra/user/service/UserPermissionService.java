package com.ark.center.auth.infra.user.service;

import com.ark.center.auth.infra.user.repository.UserPermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * 用户权限服务
 */
@Service
@RequiredArgsConstructor
public class UserPermissionService {

    private final UserPermissionRepository userPermissionRepository;

    public void refresh(Long userId) {
        userPermissionRepository.refreshUserPermissions(userId);
    }

    /**
     * 根据API ID获取用户的API权限
     */
    public boolean checkUserApiPermission(Long userId, Long apiId) {
        return userPermissionRepository.getUserApiPermission(userId, apiId) != null;
    }
}
