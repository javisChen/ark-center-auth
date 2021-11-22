package com.kt.cloud.iam.dao.mapper;

import com.kt.cloud.iam.dao.entity.IamUserRoleRel;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * <p>
 * 用户角色关联表 Mapper 接口
 * </p>
 *
 * @author
 * @since 2020-11-09
 */
public interface IamUserRoleRelMapper extends BaseMapper<IamUserRoleRel> {

    /**
     * 批量添加
     */
    void batchSaveRelation(@Param("userId") Long userId, @Param("roleIds") List<Long> roleIds);
}
