package com.kt.cloud.iam.dao.entity;


import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableLogic;
import com.kt.component.orm.mybatis.base.BaseEntity;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * <p>
 * 用户组表
 * </p>
 *
 * @author
 * @since 2020-11-09
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class IamUserGroup extends BaseEntity {

    private static final long serialVersionUID = 1L;

    /**
     * 用户组名称
     */
    @TableField("name")
    private String name;

    /**
     * 用户组名称
     */
    @TableField("pid")
    private Long pid;

    /**
     * 状态 1-已启用；2-已禁用；
     */
    @TableField("status")
    private Integer status;

    /**
     * 状态 1-已启用；2-已禁用；
     */
    @TableField("level")
    private Integer level;

    @TableField("level_path")
    private String levelPath;

    /**
     * 继承类型 0-不继承 1-继承上级用户组 2-继承所有用户组
     */
    @TableField("inherit_type")
    private Integer inheritType;

    /**
     * 用户组类型 1-公司 2-部门
     */
    @TableField("type")
    private Integer type;

    @TableField(value = "is_deleted")
    @TableLogic
    private Long isDeleted;


}
