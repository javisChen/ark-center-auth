package com.kt.upms.service.impl;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.extra.cglib.CglibUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.kt.component.dto.PageResponse;
import com.kt.model.dto.role.RoleAddDTO;
import com.kt.model.dto.role.RoleQueryDTO;
import com.kt.model.dto.role.RoleUpdateDTO;
import com.kt.model.enums.BizEnums;
import com.kt.upms.entity.UpmsRole;
import com.kt.upms.enums.RoleStatusEnum;
import com.kt.upms.mapper.UpmsPermissionRoleRelMapper;
import com.kt.upms.mapper.UpmsRoleMapper;
import com.kt.upms.mapper.UpmsUserGroupRoleRelMapper;
import com.kt.upms.service.IUpmsPermissionRoleRelService;
import com.kt.upms.service.IUpmsRoleService;
import com.kt.upms.util.Assert;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * <p>
 * 角色表 服务实现类
 * </p>
 *
 * @author 
 * @since 2020-11-09
 */
@Service
public class UpmsRoleServiceImpl extends ServiceImpl<UpmsRoleMapper, UpmsRole> implements IUpmsRoleService {

    @Autowired
    private UpmsPermissionRoleRelMapper upmsPermissionRoleRelMapper;
    @Autowired
    private UpmsUserGroupRoleRelMapper upmsUserGroupRoleRelMapper;

    @Override
    public PageResponse pageList(Page page, RoleQueryDTO params) {
        LambdaQueryWrapper<UpmsRole> queryWrapper = new LambdaQueryWrapper<UpmsRole>()
                .like(StrUtil.isNotBlank(params.getName()), UpmsRole::getName, params.getName());
        return PageResponse.success(this.page(page, queryWrapper));
    }

    @Override
    public RoleAddDTO saveRole(RoleAddDTO dto) {
        int count = countRoleByName(dto);
        Assert.isTrue(count > 0, BizEnums.ROLE_ALREADY_EXISTS);

        UpmsRole role = CglibUtil.copy(dto, UpmsRole.class);
        this.save(role);

        return dto;
    }

    private int countRoleByName(RoleAddDTO dto) {
        LambdaQueryWrapper<UpmsRole> queryWrapper = new LambdaQueryWrapper<UpmsRole>()
                .eq(UpmsRole::getName, dto.getName());
        return this.count(queryWrapper);
    }

    @Override
    public void updateRoleById(RoleUpdateDTO dto) {
        LambdaQueryWrapper<UpmsRole> queryWrapper = new LambdaQueryWrapper<UpmsRole>()
                .eq(UpmsRole::getName, dto.getName())
                .ne(UpmsRole::getId, dto.getId());
        int count = this.count(queryWrapper);
        Assert.isTrue(count > 0, BizEnums.ROLE_ALREADY_EXISTS);

        UpmsRole updateUpmsRole = CglibUtil.copy(dto, UpmsRole.class);
        this.updateById(updateUpmsRole);
    }

    @Override
    public void updateStatus(RoleUpdateDTO dto) {
        updateStatus(dto, RoleStatusEnum.DISABLED);
    }

    @Override
    public List<Long> getRoleIdsByUserId(Long userId) {
        return upmsPermissionRoleRelMapper.selectRoleIdsByUserId(userId);
    }

    @Override
    public List<Long> getRoleIdsByUserGroupIds(List<Long> userGroupIds) {
        if (CollectionUtils.isEmpty(userGroupIds)) {
            return new ArrayList<>();
        }
        return upmsUserGroupRoleRelMapper.selectRoleIdsByUserGroupIds(userGroupIds);
    }

    private void updateStatus(RoleUpdateDTO dto, RoleStatusEnum statusEnum) {
        this.update(new LambdaUpdateWrapper<UpmsRole>()
                .eq(UpmsRole::getStatus, dto.getId())
                .set(UpmsRole::getStatus, statusEnum.getValue()));
    }
}