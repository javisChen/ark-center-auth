package com.kt.upms.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.IService;
import com.kt.component.dto.PageResponse;
import com.kt.model.dto.menu.*;
import com.kt.upms.entity.UpmsRoute;

/**
 * <p>
 * 菜单表 服务类
 * </p>
 *
 * @author 
 * @since 2020-11-09
 */
public interface IUpmsRouteService extends IService<UpmsRoute> {

    PageResponse<UpmsRoute> pageList(Page page, RouteQueryDTO params);

    void saveRoute(RouteAddDTO dto);

    void updateRoute(RouteUpdateDTO dto);

    void updateRouteStatus(RouteUpdateDTO dto);

    void modifyParent(RouteModifyParentDTO dto);

    UserRoutesDTO getAllRoutes();

    RouteTreeDTO getRouteTree();

    MenuAnotherTreeDTO getRouteAnotherTree();

}
