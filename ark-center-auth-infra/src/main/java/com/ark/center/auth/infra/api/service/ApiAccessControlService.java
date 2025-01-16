package com.ark.center.auth.infra.api.service;

import cn.hutool.core.collection.CollUtil;
import com.ark.center.auth.infra.api.ApiMeta;
import com.ark.center.auth.infra.api.repository.ApiResourceRepository;
import com.ark.center.auth.infra.user.AuthUserApiPermission;
import com.ark.center.auth.infra.user.service.UserPermissionService;
import com.ark.component.security.base.user.AuthUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class ApiAccessControlService {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final ApiResourceRepository apiResourceRepository;

    /**
     * 获取API信息
     * 1. 先尝试精确匹配
     * 2. 如果精确匹配失败，尝试模式匹配
     */
    public ApiMeta getApi(String requestUri, String method) {
        // 1. 先尝试精确匹配
        ApiMeta exactMatch = apiResourceRepository.getExactApi(requestUri, method);
        if (exactMatch != null) {
            return exactMatch;
        }

        // todo 如果动态API数量有一定规模的话这里匹配会有性能问题
        //  当然我们可以尽可能地采用空间换时间的方案不断地优化，但目前来说投入太多时间来优化没有任何价值
        //  我们在定义API的时候用规范来约束尽量避免路径参数的API即可完美规避
        List<ApiMeta> dynamicApis = apiResourceRepository.getDynamicApis()
                .stream()
                .filter(api -> pathMatcher.match(api.getUri(), requestUri) && api.getMethod().equalsIgnoreCase(method))
                .toList();
        if (CollUtil.isNotEmpty(dynamicApis)) {
            return dynamicApis.getFirst();
        }
        return null;
    }
}