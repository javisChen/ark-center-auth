package com.ark.center.iam.application.user.executor;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.util.IdUtil;
import cn.hutool.crypto.digest.DigestUtil;
import com.ark.center.iam.client.user.command.UserCmd;
import com.ark.center.iam.domain.role.service.RoleAssignService;
import com.ark.center.iam.domain.user.gateway.UserGateway;
import com.ark.center.iam.domain.user.support.IUserPasswordHelper;
import com.ark.center.iam.domain.usergroup.service.UserGroupAssignService;
import com.ark.center.iam.infra.user.converter.UserBeanConverter;
import com.ark.center.iam.domain.user.User;
import com.ark.component.exception.ExceptionFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserCreateCmdExe {

    private final UserBeanConverter beanConverter;

    private final UserGateway userGateway;

    private final RoleAssignService roleAssignService;

    private final UserGroupAssignService userGroupAssignService;

    private final IUserPasswordHelper userPasswordHelper;

    public Long execute(UserCmd userCmd) {
        log.info("[User]: Begin Create User, User = {}", userCmd);
        User user = beanConverter.toUserDO(userCmd);

        // 信息有效性校验
        validityCheck(user);

        // 初始化一些用户信息
        initUser(user);

        // 持久化用户
        persistUser(user);

        // 持久化后一些操作
        postPersistUser(user, userCmd);

        // todo 发布事件
        return user.getId();
    }

    private void validityCheck(User user) {

        // 检查用户手机号
        checkUserPhone(user);
    }

    private void initUser(User user) {
        // 生成用户编码
        user.setCode(generateUserCode());

        // 用户密码=bcrypt(前端md5(md5(password)) + salt)
        user.setPassword(userPasswordHelper.enhancePassword(DigestUtil.md5Hex(user.getPassword())));

    }

    private String generateUserCode() {
        // 生成后先查询一遍，防止生成了重复的code，其实几率微乎其微
        String code = IdUtil.fastUUID();
        if (codeExists(code)) {
            return generateUserCode();
        }
        return code;
    }

    private boolean codeExists(String code) {
        return userGateway.countUserByCode(code) > 0;
    }

    /**
     * 持久化用户后的操作
     *
     * @param user   用户
     * @param createCmd 创建用户请求
     */
    private void postPersistUser(User user, UserCmd createCmd) {

        Long userId = user.getId();

        // 分配角色
        assignRoles(userId, createCmd.getRoleIds());

        // 分配用户组
        assignUserGroups(userId, createCmd.getUserGroupIds());
    }

    private void persistUser(User user) {
        userGateway.insert(user);
    }

    private void checkUserPhone(User user) {
        long count = userGateway.countUserByPhone(user.getPhone());
        cn.hutool.core.lang.Assert.isTrue(count > 0, () -> ExceptionFactory.userException("手机号码已存在"));
    }

    private void assignUserGroups(Long userId, List<Long> userGroupIds) {
        if (CollectionUtil.isNotEmpty(userGroupIds)) {
            userGroupAssignService.assignUserGroups(userId, userGroupIds);
        }
    }

    private void assignRoles(Long userId, List<Long> roleIds) {
        if (CollectionUtil.isNotEmpty(roleIds)) {
            roleAssignService.assignUserRoles(userId, roleIds);
        }
    }

}