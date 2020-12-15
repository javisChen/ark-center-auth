package com.kt.upms.api.controller;


import cn.hutool.extra.cglib.CglibUtil;
import com.kt.component.dto.PageRequest;
import com.kt.component.dto.ServerResponse;
import com.kt.component.web.base.BaseController;
import com.kt.model.dto.permission.PermissionAddDTO;
import com.kt.model.dto.permission.PermissionQueryDTO;
import com.kt.model.dto.permission.PermissionUpdateDTO;
import com.kt.model.validgroup.UpmsValidateGroup;
import com.kt.upms.entity.UpmsPermission;
import com.kt.upms.service.IUpmsPermissionService;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.groups.Default;


/**
 * <p>
 * 权限表 前端控制器
 * </p>
 *
 * @author
 * @since 2020-11-09
 */
@RestController
@RequestMapping
public class UpmsPermissionController extends BaseController {

    private final IUpmsPermissionService iUpmsPermissionService;

    public UpmsPermissionController(IUpmsPermissionService iUpmsPermissionService) {
        this.iUpmsPermissionService = iUpmsPermissionService;
    }

    @PostMapping("/permissions")
    public ServerResponse list(@RequestBody PageRequest<PermissionQueryDTO> pageRequest) {
        return ServerResponse.ok(iUpmsPermissionService.pageList(getPage(pageRequest), pageRequest.getParams()));
    }

    @PostMapping("/permission")
    public ServerResponse add(@RequestBody @Validated PermissionAddDTO dto) {
        return ServerResponse.ok(iUpmsPermissionService.savePermission(dto));
    }

    @PutMapping("/permission")
    public ServerResponse update(@RequestBody @Validated PermissionUpdateDTO dto) {
        iUpmsPermissionService.updatePermissionById(dto);
        return ServerResponse.ok();
    }

    @GetMapping("/permission/{id}")
    public ServerResponse get(@PathVariable("id") String id) {
        UpmsPermission upmsPermission = iUpmsPermissionService.getById(id);
        if (upmsPermission == null) {
            return ServerResponse.ok();
        }
        return ServerResponse.ok(CglibUtil.copy(upmsPermission, PermissionQueryDTO.class));
    }

    @PutMapping("/permission/status")
    public ServerResponse updateStatus(@Validated({UpmsValidateGroup.UpdateStatus.class, Default.class})
                                       @RequestBody PermissionUpdateDTO dto) {
        iUpmsPermissionService.updateStatus(dto);
        return ServerResponse.ok();
    }
}

