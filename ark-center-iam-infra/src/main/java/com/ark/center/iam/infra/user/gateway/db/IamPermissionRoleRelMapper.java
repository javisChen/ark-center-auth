package com.ark.center.iam.infra.user.gateway.db;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.ark.center.iam.dao.entity.IamPermissionRoleRel;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * <p>
 * 角色与权限关联表 Mapper 接口
 * </p>
 *
 * @author
 * @since 2020-11-09
 */
public interface IamPermissionRoleRelMapper extends BaseMapper<IamPermissionRoleRel> {

    void batchInsert(@Param("roleId") Long roleId,
                     @Param("permissionIds") List<Long> permissionIds);

    List<String> selectRoleNamesByUserId(@Param("userId") Long userId);
    List<Long> selectRoleIdsByUserGroupId(@Param("userGroupId") Long userGroupId);

    List<String> selectRoleNamesByUserGroupId(@Param("userGroupId") Long userGroupId);
}
