package com.ark.center.iam.infra.usergroup.gateway.db;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * <p>
 * 用户组与角色关联表 Mapper 接口
 * </p>
 *
 * @author
 * @since 2020-11-09
 */
public interface UserGroupRoleRelMapper extends BaseMapper<IamUserGroupRoleRel> {

    int deleteByRoleIdsAndUserGroupId(@Param("userGroupId") Long userGroupId,
                                      @Param("roleIds") List<Long> roleIds);

    void insertBatch(@Param("userGroupId") Long id, @Param("roleIds") List<Long> roleIds);

    List<Long> selectRoleIdsByUserGroupIds(@Param("userGroupIds") List<Long> userGroupIds);

}
