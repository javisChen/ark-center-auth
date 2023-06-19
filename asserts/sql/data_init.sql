TRUNCATE TABLE auth_route;
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (2, 1, '个人页', 'account', 'RouteView', 0, '2.', 1, '', 'user', 0, 1, 700, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (3, 1, '结果页', 'result', 'PageView', 0, '3.', 1, '', 'check-circle-o', 0, 1, 500, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (4, 1, '详情页', 'profile', 'RouteView', 0, '4.', 1, '', 'profile', 0, 1, 400, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (5, 1, '列表页', 'list', 'RouteView', 0, '5.', 1, '', 'table', 0, 1, 300, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (6, 1, '仪表盘', 'dashboard', 'RouteView', 0, '6.', 1, '', 'dashboard', 0, 1, 100, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (7, 1, '异常页', 'exception', 'RouteView', 0, '7.', 1, '', 'warning', 0, 1, 600, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (8, 1, '工作台', 'workplace', 'Workplace', 6, '6.8.', 2, '/dashboard/workplace', '', 0, 1, 102, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (9, 1, '分析页', 'Analysis', 'Analysis', 6, '6.9.', 2, '/dashboard/analysis/:pageNo([1-9]\\\\d*)?', '', 0, 1, 101,
        1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (13, 1, '查询表格', 'table-list', 'TableList', 5, '5.13.', 2, '/list/table-list/:pageNo([1-9]\\\\d*)?', '', 0, 1, 0,
        1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (14, 1, '标准列表', 'basic-list', 'StandardList', 5, '5.14.', 2, '/list/basic-list', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (15, 1, '卡片列表', 'card', 'CardList', 5, '5.15.', 2, '/list/card', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (16, 1, '搜索列表', 'search', 'SearchLayout', 5, '5.16.', 2, '/list/search', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (17, 1, '基础详情页', 'basic', 'ProfileBasic', 4, '4.17.', 2, '/profile/basic', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (18, 1, '高级详情页', 'advanced', 'ProfileAdvanced', 4, '4.18.', 2, '/profile/advanced', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (19, 1, '成功', 'success', 'ResultSuccess', 3, '3.19.', 2, '/result/success', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (20, 1, '失败', 'fail', 'ResultFail', 3, '3.20.', 2, '/result/fail', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (22, 1, '404', '404', 'Exception404', 7, '7.22.', 2, '/exception/404', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (23, 1, '500', '500', 'Exception500', 7, '7.23.', 2, '/exception/500', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (24, 1, '个人中心', 'center', 'AccountCenter', 2, '2.24.', 2, '/account/center', '', 0, 2, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (25, 1, '个人设置', 'settings', 'AccountSettings', 2, '2.25.', 2, '/account/settings', '', 1, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (26, 1, '搜索列表（项目）', 'project', 'SearchProjects', 16, '5.16.26.', 2, '/list/search/project', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (27, 1, '搜索列表（应用）', 'application', 'SearchApplications', 16, '5.16.27.', 2, '/list/search/application', '', 0, 1,
        0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (28, 1, '基本设置', 'BasicSettings', 'BasicSettings', 25, '2.25.28.', 3, '/account/settings/basic', '', 0, 2, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (29, 1, '安全设置', 'SecuritySettings', 'SecuritySettings', 25, '2.25.29.', 3, '/account/settings/security', '', 0,
        2, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (30, 1, '个性化设置', 'CustomSettings', 'CustomSettings', 25, '2.25.30.', 3, '/account/settings/custom', '', 0, 2, 0,
        1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (32, 1, '新消息通知', 'NotificationSettings', 'NotificationSettings', 25, '2.25.32.', 3,
        '/account/settings/notification', '', 0, 2, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (34, 1, '搜索列表（文章）', 'article', 'SearchArticles', 16, '5.16.27.', 3, '/list/search/article', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (35, 1, '其他组件', 'other', 'PageView', 0, '35.', 1, '', 'slack', 0, 1, 800, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (36, 1, 'IconSelector', 'TestIconSelect', 'EditList', 35, '35.36.', 2, '/other/icon-selector', 'tool', 0, 1, 810,
        1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (37, 1, '业务布局', 'bizLayout', 'RouteView', 35, '35.37.', 2, '', 'layout', 0, 1, 820, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (38, 1, '树目录表格', 'TreeList', 'TreeList', 37, '35.37.38.', 3, '/other/list/tree-list', '', 0, 1, 821, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (39, 1, '内联编辑表格', 'EditList', 'EditList', 37, '35.37.39.', 3, '/other/list/edit-table', '', 0, 1, 822, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (40, 1, '权限列表', 'PermissionList', 'PermissionList', 37, '35.37.40.', 3, '/other/list/system-permission', '', 0, 1, 823, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (42, 1, '角色列表', 'RoleList', 'RoleList', 37, '35.37.42.', 3, '/other/list/role-list', '', 0, 1, 825, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (43, 1, '角色列表2', 'SystemRole', 'SystemRole', 37, '35.37.43.', 3, '/other/list/system-role', '', 0, 1, 826, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (44, 1, '权限管理', 'permission', 'RouteView', 0, '44.', 1, '/permission', 'slack', 0, 1, 1, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (45, 1, '路由管理', 'permission:route', 'PermissionRoute', 44, '44.45.', 2, '/permission/route', '', 0, 2, 910, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (57, 1, '表单页', 'form', 'RouteView', 0, '57.', 1, '', 'form', 0, 1, 2, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (58, 1, '高级表单', 'advanced-form', 'AdvanceForm', 57, '57.58.', 2, '/form/advanced-form', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (59, 1, '分步表单', 'step-form', 'StepForm', 57, '57.59.', 2, '/form/step-form', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (60, 1, '基础表单', 'basic-form', 'BasicForm', 57, '57.60.', 2, '/form/base-form', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (70, 1, '测试子路由', '3213', '', 69, '6.70.', 2, '', '', 0, 1, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (71, 1, '用户管理', 'permission:user', 'PermissionUser', 44, '44.71.', 2, '/permission/user', '', 0, 2, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (72, 1, '用户组管理', 'permission:usergroup', 'PermissionUserGroup', 44, '44.72.', 2, '/permission/usergroup', '', 0,
        2, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (73, 1, '账号绑定', 'BindingSettings', 'BindingSettings', 25, '2.25.73.', 3, '/account/settings/binding', '', 0, 1,
        0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (74, 1, '角色管理', 'permission:role', 'PermissionRole', 44, '44.74.', 2, '/permission/role', '', 0, 2, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (75, 1, '应用管理', 'permission:application', 'PermissionApplication', 44, '44.75.', 2, '/permission/application',
        '', 0, 2, 0, 1);
INSERT INTO kt.auth_route (id, application_id, name, code, component, pid, level_path, level, path, icon, hide_children,
                          type, sequence, status)
VALUES (76, 1, '接口管理', 'permission:interface', 'PermissionApi', 44, '44.76.', 2, '/permission/interface', '', 0, 2, 0,
        1);
TRUNCATE TABLE auth_permission;
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (1, 'FR00001', 'FRONT_ROUTE', 1, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (2, 'FR00002', 'FRONT_ROUTE', 2, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (3, 'FR00003', 'FRONT_ROUTE', 3, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (4, 'FR00004', 'FRONT_ROUTE', 4, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (5, 'FR00005', 'FRONT_ROUTE', 5, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (6, 'FR00006', 'FRONT_ROUTE', 6, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (7, 'FR00007', 'FRONT_ROUTE', 7, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (8, 'FR00008', 'FRONT_ROUTE', 8, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (9, 'FR00009', 'FRONT_ROUTE', 9, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (10, 'FR00010', 'FRONT_ROUTE', 10, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (11, 'FR00011', 'FRONT_ROUTE', 11, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (12, 'FR00012', 'FRONT_ROUTE', 12, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (13, 'FR00013', 'FRONT_ROUTE', 13, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (14, 'FR00014', 'FRONT_ROUTE', 14, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (15, 'FR00015', 'FRONT_ROUTE', 15, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (16, 'FR00016', 'FRONT_ROUTE', 16, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (17, 'FR00017', 'FRONT_ROUTE', 17, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (18, 'FR00018', 'FRONT_ROUTE', 18, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (19, 'FR00019', 'FRONT_ROUTE', 19, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (20, 'FR00020', 'FRONT_ROUTE', 20, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (21, 'FR00021', 'FRONT_ROUTE', 21, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (22, 'FR00022', 'FRONT_ROUTE', 22, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (23, 'FR00023', 'FRONT_ROUTE', 23, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (24, 'FR00024', 'FRONT_ROUTE', 24, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (25, 'FR00025', 'FRONT_ROUTE', 25, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (26, 'FR00026', 'FRONT_ROUTE', 26, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (27, 'FR00027', 'FRONT_ROUTE', 27, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (28, 'FR00028', 'FRONT_ROUTE', 28, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (29, 'FR00029', 'FRONT_ROUTE', 29, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (30, 'FR00030', 'FRONT_ROUTE', 30, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (31, 'FR00031', 'FRONT_ROUTE', 31, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (32, 'FR00032', 'FRONT_ROUTE', 32, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (33, 'FR00033', 'FRONT_ROUTE', 33, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (34, 'FR00035', 'FRONT_ROUTE', 35, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (35, 'FR00036', 'FRONT_ROUTE', 36, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (36, 'FR00037', 'FRONT_ROUTE', 37, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (37, 'FR00038', 'FRONT_ROUTE', 38, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (38, 'FR00039', 'FRONT_ROUTE', 39, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (39, 'FR00040', 'FRONT_ROUTE', 40, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (40, 'FR00041', 'FRONT_ROUTE', 41, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (41, 'FR00042', 'FRONT_ROUTE', 42, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (42, 'FR00043', 'FRONT_ROUTE', 43, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (43, 'FR00044', 'FRONT_ROUTE', 44, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (44, 'FR00045', 'FRONT_ROUTE', 45, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (45, 'FR00046', 'FRONT_ROUTE', 46, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (46, 'FR00047', 'FRONT_ROUTE', 47, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (47, 'FR00048', 'FRONT_ROUTE', 48, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (48, 'FR00049', 'FRONT_ROUTE', 49, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (49, 'FR00050', 'FRONT_ROUTE', 50, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (50, 'FR00051', 'FRONT_ROUTE', 51, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (51, 'FR00052', 'FRONT_ROUTE', 52, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (52, 'FR00053', 'FRONT_ROUTE', 53, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (53, 'FR00054', 'FRONT_ROUTE', 54, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (54, 'FR00055', 'FRONT_ROUTE', 55, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (55, 'FR00056', 'FRONT_ROUTE', 56, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (56, 'FR00057', 'FRONT_ROUTE', 57, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (57, 'FR00058', 'FRONT_ROUTE', 58, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (58, 'FR00059', 'FRONT_ROUTE', 59, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (59, 'FR00060', 'FRONT_ROUTE', 60, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (60, 'FR00061', 'FRONT_ROUTE', 61, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (61, 'FR00062', 'FRONT_ROUTE', 62, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (62, 'FR00063', 'FRONT_ROUTE', 63, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (63, 'FR00064', 'FRONT_ROUTE', 64, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (64, 'FR00065', 'FRONT_ROUTE', 65, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (65, 'FR00066', 'FRONT_ROUTE', 66, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (66, 'FR00067', 'FRONT_ROUTE', 67, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (67, 'FR00068', 'FRONT_ROUTE', 68, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (68, 'FR00069', 'FRONT_ROUTE', 69, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (69, 'FR00070', 'FRONT_ROUTE', 70, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (70, 'FR00071', 'FRONT_ROUTE', 71, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (71, 'FR00072', 'FRONT_ROUTE', 72, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (72, 'FR00073', 'FRONT_ROUTE', 73, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (73, 'FR00074', 'FRONT_ROUTE', 74, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (74, 'FR00075', 'FRONT_ROUTE', 75, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (75, 'FR00076', 'FRONT_ROUTE', 76, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (76, 'FR00034', 'FRONT_ROUTE', 34, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (77, 'IA00001', 'SER_API', 1, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (78, 'IA00002', 'SER_API', 2, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (79, 'IA00003', 'SER_API', 3, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (80, 'IA00004', 'SER_API', 4, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (81, 'IA00005', 'SER_API', 5, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (82, 'IA00006', 'SER_API', 6, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (83, 'IA00007', 'SER_API', 7, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (84, 'IA00008', 'SER_API', 8, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (85, 'IA00009', 'SER_API', 9, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (86, 'IA00010', 'SER_API', 10, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (87, 'IA00011', 'SER_API', 11, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (88, 'IA00012', 'SER_API', 12, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (89, 'IA00013', 'SER_API', 13, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (90, 'IA00014', 'SER_API', 14, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (91, 'IA00015', 'SER_API', 15, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (92, 'IA00016', 'SER_API', 16, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (93, 'IA00017', 'SER_API', 17, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (94, 'IA00018', 'SER_API', 18, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (95, 'IA00019', 'SER_API', 19, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (96, 'IA00020', 'SER_API', 20, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (97, 'IA00021', 'SER_API', 21, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (98, 'IA00022', 'SER_API', 22, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (99, 'IA00023', 'SER_API', 23, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (100, 'IA00024', 'SER_API', 24, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (101, 'IA00025', 'SER_API', 25, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (102, 'IA00026', 'SER_API', 26, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (103, 'IA00027', 'SER_API', 27, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (104, 'IA00028', 'SER_API', 28, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (105, 'IA00029', 'SER_API', 29, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (106, 'IA00030', 'SER_API', 30, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (107, 'IA00031', 'SER_API', 31, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (108, 'IA00032', 'SER_API', 32, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (109, 'IA00033', 'SER_API', 33, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (110, 'IA00034', 'SER_API', 34, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (111, 'IA00035', 'SER_API', 35, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (112, 'IA00036', 'SER_API', 36, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (113, 'IA00037', 'SER_API', 37, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (114, 'IA00038', 'SER_API', 38, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (115, 'IA00039', 'SER_API', 39, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (116, 'IA00040', 'SER_API', 40, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (117, 'IA00041', 'SER_API', 41, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (118, 'IA00042', 'SER_API', 42, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (119, 'IA00043', 'SER_API', 43, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (120, 'IA00044', 'SER_API', 44, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (121, 'IA00045', 'SER_API', 45, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (122, 'IA00046', 'SER_API', 46, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (123, 'IA00047', 'SER_API', 47, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (124, 'IA00048', 'SER_API', 48, 1);
INSERT INTO kt.auth_permission (id, code, type, resource_id, status)
VALUES (125, 'IA00049', 'SER_API', 49, 1);
TRUNCATE TABLE auth_permission_role_rel;
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (44, 1, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (45, 2, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (46, 3, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (47, 4, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (48, 5, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (49, 6, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (50, 7, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (51, 8, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (52, 9, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (53, 10, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (54, 11, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (55, 12, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (56, 13, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (57, 14, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (58, 15, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (59, 16, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (60, 17, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (61, 18, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (62, 19, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (63, 20, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (64, 21, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (65, 22, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (66, 23, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (67, 24, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (68, 25, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (69, 26, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (70, 27, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (71, 28, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (72, 29, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (73, 30, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (74, 31, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (75, 32, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (76, 33, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (77, 34, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (78, 35, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (79, 36, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (80, 37, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (81, 38, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (82, 39, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (83, 40, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (84, 41, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (85, 42, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (86, 43, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (87, 70, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (88, 71, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (89, 73, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (90, 75, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (91, 76, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (92, 44, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (93, 56, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (94, 57, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (95, 58, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (96, 59, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (97, 74, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (98, 77, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (99, 78, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (100, 79, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (101, 80, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (102, 81, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (103, 82, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (104, 83, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (105, 84, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (106, 85, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (107, 86, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (108, 87, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (109, 88, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (110, 89, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (111, 90, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (112, 91, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (113, 92, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (114, 93, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (115, 94, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (116, 95, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (117, 96, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (118, 97, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (119, 98, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (120, 99, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (121, 100, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (122, 101, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (123, 102, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (124, 103, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (125, 104, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (126, 105, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (127, 106, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (128, 107, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (129, 108, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (130, 109, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (131, 110, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (132, 111, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (133, 112, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (134, 113, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (135, 114, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (136, 115, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (137, 116, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (138, 117, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (139, 118, 1);
INSERT INTO kt.auth_permission_role_rel (id, permission_id, role_id)
VALUES (140, 119, 1);
TRUNCATE TABLE auth_user;
INSERT INTO kt.auth_user (id, name, phone, code, password, status)
VALUES (1, 'Admin', 'Admin', 'SuperAdmin', '$2a$10$79zDkVaAzVBa2otTZ82vkea4MBFQfqnNxHArRSTXc2zeZrgNEHYDa', 1);
TRUNCATE TABLE auth_role;
INSERT INTO kt.auth_role (id, name, status)
VALUES (1, '超级管理员', 1);
TRUNCATE TABLE auth_user_role_rel;
INSERT INTO kt.auth_user_role_rel (id, user_id, role_id)
VALUES (1, 1, 1);
TRUNCATE TABLE auth_api;
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (1, 1, '/api/category', '/api/category', 'PUT', 1, 5, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (2, 1, '/api/category', '/api/category', 'DELETE', 1, 5, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (3, 1, '/api/categories', '/api/categories', 'GET', 1, 5, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (4, 1, '/api/category', '/api/category', 'POST', 1, 5, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (5, 1, '/api/init', '/api/init', 'GET', 1, 5, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (6, 1, '/apis', '/apis', 'POST', 1, 5, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (7, 1, '/api/test', '/api/test', 'GET', 1, 5, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (8, 1, '/api', '/api', 'POST', 1, 5, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (9, 1, '/api', '/api', 'PUT', 1, 5, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (10, 1, '/api/{id}', '/api/{id}', 'DELETE', 1, 5, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (11, 1, '/api/cache', '/api/cache', 'PUT', 1, 5, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (12, 1, '/applications', '/applications', 'POST', 1, 4, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (13, 1, '/application', '/application', 'POST', 1, 4, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (14, 1, '/application', '/application', 'PUT', 1, 4, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (15, 1, '/auth/login', '/auth/login', 'POST', 1, 0, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (16, 1, '/roles/all', '/roles/all', 'GET', 1, 3, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (17, 1, '/role/status', '/role/status', 'PUT', 1, 3, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (18, 1, '/role', '/role', 'POST', 1, 3, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (19, 1, '/role/{id}', '/role/{id}', 'GET', 1, 3, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (20, 1, '/role', '/role', 'PUT', 1, 3, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (21, 1, '/roles', '/roles', 'POST', 1, 3, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (22, 1, '/role/permission/route', '/role/permission/route', 'POST', 1, 3, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (23, 1, '/role/permission/api', '/role/permission/api', 'POST', 1, 3, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (24, 1, '/role/permission/routes', '/role/permission/routes', 'GET', 1, 3, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (25, 1, '/role/permission/elements', '/role/permission/elements', 'GET', 1, 3, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (26, 1, '/role/permission/apis', '/role/permission/apis', 'GET', 1, 3, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (27, 1, '/route/status', '/route/status', 'PUT', 1, 6, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (28, 1, '/route/parent', '/route/parent', 'PUT', 1, 6, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (29, 1, '/route', '/route', 'POST', 1, 6, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (30, 1, '/route/{id}', '/route/{id}', 'GET', 1, 6, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (31, 1, '/route', '/route', 'PUT', 1, 6, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (32, 1, '/routes/init', '/routes/init', 'POST', 1, 6, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (33, 1, '/routes/all', '/routes/all', 'POST', 1, 6, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (34, 1, '/routes', '/routes', 'POST', 1, 6, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (35, 1, '/route/{id}', '/route/{id}', 'DELETE', 1, 6, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (36, 1, '/route/{routeId}/elements', '/route/{routeId}/elements', 'GET', 1, 6, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (37, 1, '/user', '/user', 'POST', 1, 1, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (38, 1, '/user', '/user', 'GET', 1, 1, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (39, 1, '/user', '/user', 'PUT', 1, 1, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (40, 1, '/users', '/users', 'POST', 1, 1, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (41, 1, '/user/info', '/user/info', 'GET', 1, 1, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (42, 1, '/user/permission/routes', '/user/permission/routes', 'GET', 1, 1, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (43, 1, '/user/permission/elements', '/user/permission/elements', 'GET', 1, 2, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (44, 1, '/usergroup/status', '/usergroup/status', 'PUT', 1, 2, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (45, 1, '/usergroup', '/usergroup', 'POST', 1, 2, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (46, 1, '/usergroup', '/usergroup', 'PUT', 1, 2, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (47, 1, '/usergroups/all', '/usergroups/all', 'GET', 1, 2, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (48, 1, '/usergroups', '/usergroups', 'POST', 1, 2, 3, 0);
INSERT INTO kt.auth_api (id, application_id, name, url, method, status, category_id, auth_type, has_path_variable)
VALUES (49, 1, '/usergroups/tree', '/usergroups/tree', 'POST', 1, 2, 3, 0);
TRUNCATE TABLE auth_application;
INSERT INTO kt.auth_application (id, name, code, status, type) VALUES (1, '权限中心', 'permission', 1, 1);
TRUNCATE TABLE auth_api_category;
INSERT INTO kt.auth_api_category (id, application_id, name)
VALUES (1, 1, '用户管理');
INSERT INTO kt.auth_api_category (id, application_id, name)
VALUES (2, 1, '用户组管理');
INSERT INTO kt.auth_api_category (id, application_id, name)
VALUES (3, 1, '角色管理');
INSERT INTO kt.auth_api_category (id, application_id, name)
VALUES (4, 1, '应用管理');
INSERT INTO kt.auth_api_category (id, application_id, name)
VALUES (5, 1, '接口管理');
INSERT INTO kt.auth_api_category (id, application_id, name)
VALUES (6, 1, '路由管理');
INSERT INTO kt.auth_api_category (id, application_id, name)
VALUES (7, 2, '订单管理');