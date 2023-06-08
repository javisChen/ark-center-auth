package com.ark.center.iam.application.user;

import com.ark.center.iam.application.user.executor.UserSelfQryExe;
import com.ark.center.iam.client.permission.vo.PermissionDTO;
import com.ark.center.iam.client.user.dto.UserRouteDTO;
import com.ark.center.iam.domain.user.service.UserPermissionService;
import com.ark.component.context.core.ServiceContext;
import com.ark.component.security.base.user.LoginUserContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserSelfAppService {

    private final UserSelfQryExe userSelfQryExe;

    public LoginUserContext queryUserSelf() {
        return ServiceContext.getCurrentUser();
    }

    public List<UserRouteDTO> queryUserSelfRoutes() {
        return userSelfQryExe.queryUserSelfRoutes();
    }

    public List<PermissionDTO> queryUserSelfElements() {
        return userSelfQryExe.queryUserSelfElements();
    }

}
