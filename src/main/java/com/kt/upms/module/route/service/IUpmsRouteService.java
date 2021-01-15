package com.kt.upms.module.route.service;


import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.IService;
import com.kt.upms.entity.UpmsRoute;
import com.kt.upms.module.route.dto.*;
import com.kt.upms.module.route.vo.RouteDetailVO;
import com.kt.upms.module.route.vo.RouteElementVO;
import com.kt.upms.module.route.vo.RouteListTreeVO;

import java.util.List;

/**
 * <p>
 * 菜单表 服务类
 * </p>
 *
 * @author 
 * @since 2020-11-09
 */
public interface IUpmsRouteService extends IService<UpmsRoute> {

    Page<RouteListTreeVO> pageList(RouteQueryDTO pageRequest);

    void saveRoute(RouteUpdateDTO dto);

    void updateRoute(RouteUpdateDTO dto);

    void updateRouteStatus(RouteUpdateDTO dto);

    void modifyParent(RouteModifyParentDTO dto);

    RouteDetailVO getRoute(Long id);

    UserRoutesDTO getUserRoutes();

    void deleteRouteById(Long id);

    List<RouteListTreeVO> listAllVOs(RouteQueryDTO dto);

    List<RouteElementVO> listRouteElementsById(Long routeId);

    String getRouteNameById(Long pid);
}
