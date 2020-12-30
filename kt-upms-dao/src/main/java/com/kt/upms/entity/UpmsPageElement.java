package com.kt.upms.entity;

import com.baomidou.mybatisplus.annotation.TableField;
import com.kt.component.db.base.BaseEntity;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * <p>
 * 页面元素表
 * </p>
 *
 * @author 
 * @since 2020-11-09
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class UpmsPageElement extends BaseEntity {

    private static final long serialVersionUID = 1L;

    /**
     * 所属菜单id，关联upms_menu.id
     */
    @TableField("menu_id")
    private Long menuId;

    /**
     * 元素名称
     */
    @TableField("name")
    private String name;

    /**
     * 元素类型 1-按钮；2-层；
     */
    @TableField("type")
    private Integer type;

}