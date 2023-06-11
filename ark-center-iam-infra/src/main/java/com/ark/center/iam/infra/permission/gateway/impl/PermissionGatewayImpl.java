package com.ark.center.iam.infra.permission.gateway.impl;

import cn.hutool.core.collection.CollectionUtil;
import com.ark.center.iam.client.permission.vo.PermissionDTO;
import com.ark.center.iam.domain.permission.Permission;
import com.ark.center.iam.domain.permission.enums.PermissionStatusEnums;
import com.ark.center.iam.domain.permission.gateway.PermissionGateway;
import com.ark.center.iam.infra.permission.assembler.PermissionAssembler;
import com.ark.center.iam.infra.permission.gateway.db.PermissionMapper;
import com.ark.center.iam.infra.permission.gateway.db.PermissionRoleRel;
import com.ark.center.iam.infra.permission.gateway.db.PermissionRoleRelMapper;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Repository
@RequiredArgsConstructor
public class PermissionGatewayImpl extends ServiceImpl<PermissionMapper, Permission> implements PermissionGateway {

    private final PermissionRoleRelMapper permissionRoleRelMapper;
    private final PermissionAssembler permissionAssembler;

    @Override
    public List<Permission> selectByType(String permissionType) {
        return lambdaQuery()
                .eq(Permission::getType, permissionType)
                .eq(Permission::getStatus, PermissionStatusEnums.ENABLED.getValue())
                .list();
    }

    @Override
    public List<Permission> selectByTypeAndRoleIds(List<Long> roleIds, String permissionType) {
        if (CollectionUtil.isEmpty(roleIds)) {
            return Collections.emptyList();
        }
        return baseMapper.selectByRoleIdsAndType(roleIds, permissionType);
    }

    @Override
    public void insert(Permission permission) {
        save(permission);
    }

    @Override
    public void deletePermissionAndRoleRelationsByRoleId(Long roleId) {
        LambdaUpdateWrapper<PermissionRoleRel> qw = new LambdaUpdateWrapper<>();
        qw.eq(PermissionRoleRel::getRoleId, roleId);
        permissionRoleRelMapper.delete(qw);
    }

    @Override
    public void deleteRolePermission(Long roleId, List<Long> permissionIds) {
        if (CollectionUtil.isNotEmpty(permissionIds)) {
            LambdaQueryWrapper<PermissionRoleRel> qw = new LambdaQueryWrapper<PermissionRoleRel>()
                    .eq(PermissionRoleRel::getRoleId, roleId)
                    .in(PermissionRoleRel::getPermissionId, permissionIds);
            permissionRoleRelMapper.delete(qw);
        }
    }

    @Override
    public void insertBatchRolePermissionRelations(Long roleId, List<Long> permissionIds) {
        if (CollectionUtil.isNotEmpty(permissionIds)) {
            permissionRoleRelMapper.batchInsert(roleId, permissionIds);
        }
    }

    @Override
    public List<PermissionDTO> selectRolePermissions(Long applicationId, Long roleId, String permissionType) {
        List<Permission> permissions = this.baseMapper.selectByRoleIdAndType(applicationId, roleId, permissionType);
        return permissions.stream().map(permissionAssembler::toPermissionDTO).collect(Collectors.toList());
    }

}
