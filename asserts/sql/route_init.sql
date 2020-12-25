truncate table upms_route;

INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (28, '基本设置', 'BasicSettings', 'BasicSettings', '/account/settings/basic', 0, 25, '1.2.3.', 3, 0, '', 1, '2020-12-24 16:13:50', '2020-12-24 16:13:50', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (29, '安全设置', 'SecuritySettings', 'SecuritySettings', '/account/settings/security', 0, 25, '1.2.3.', 3, 0, '', 1, '2020-12-24 16:13:50', '2020-12-24 16:13:50', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (30, '个性化设置', 'CustomSettings', 'CustomSettings', '/account/settings/custom', 0, 25, '1.2.3.', 3, 0, '', 1, '2020-12-24 16:13:50', '2020-12-24 16:13:50', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (31, '账户绑定', 'BindingSettings', 'BindingSettings', '/account/settings/binding', 0, 25, '1.2.3.', 3, 0, '', 1, '2020-12-24 16:13:50', '2020-12-24 16:13:50', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (32, '新消息通知', 'NotificationSettings', 'NotificationSettings', '/account/settings/notification', 0, 25, '1.2.3.', 3, 0, '', 1, '2020-12-24 16:13:50', '2020-12-24 16:13:50', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (34, '搜索列表（文章）', 'article', 'SearchArticles', '/list/search/article', 0, 16, '1.2.3.', 3, 0, '', 1, '2020-12-24 23:55:30', '2020-12-24 23:55:30', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (38, '树目录表格', 'TreeList', 'TreeList', '/other/list/tree-list', 0, 37, '1.2.3.', 3, 821, '', 1, '2020-12-25 17:23:24', '2020-12-25 17:23:24', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (39, '内联编辑表格', 'EditList', 'EditList', '/other/list/edit-table', 0, 37, '1.2.3.', 3, 822, '', 1, '2020-12-25 17:23:25', '2020-12-25 17:23:25', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (40, '权限列表', 'PermissionList', 'PermissionList', '/other/list/system-role', 0, 37, '1.2.3.', 3, 823, '', 1, '2020-12-25 17:23:25', '2020-12-25 17:23:25', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (41, '用户列表', 'UserList', 'UserList', '/other/list/user-list', 0, 37, '1.2.3.', 3, 824, '', 1, '2020-12-25 17:23:25', '2020-12-25 17:23:25', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (42, '角色列表', 'RoleList', 'RoleList', '/other/list/role-list', 0, 37, '1.2.3.', 3, 825, '', 1, '2020-12-25 17:23:25', '2020-12-25 17:23:25', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (43, '角色列表2', 'SystemRole', 'SystemRole', '/other/list/system-role', 0, 37, '1.2.3.', 3, 826, '', 1, '2020-12-25 17:23:25', '2020-12-25 17:23:25', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (10, '基础表单', 'basic-form', 'BasicForm', '/form/base-form', 0, 1, '1.2.', 2, 0, '', 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (11, '分步表单', 'step-form', 'StepForm', '/form/step-form', 0, 1, '1.2.', 2, 0, '', 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (12, '高级表单', 'advanced-form', 'AdvanceForm', '/form/advance-form', 0, 1, '1.2.', 2, 0, '', 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (13, '查询表格', 'table-list', 'TableList', '/list/table-list/:pageNo([1-9]\\\\d*)?', 0, 5, '1.2.', 2, 0, '', 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (14, '标准列表', 'basic-list', 'StandardList', '/list/basic-list', 0, 5, '1.2.', 2, 0, '', 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (15, '卡片列表', 'card', 'CardList', '/list/card', 0, 5, '1.2.', 2, 0, '', 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (16, '搜索列表', 'search', 'SearchLayout', '/list/search', 0, 5, '1.2.', 2, 0, '', 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (17, '基础详情页', 'basic', 'ProfileBasic', '/profile/basic', 0, 4, '1.2.', 2, 0, '', 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (18, '高级详情页', 'advanced', 'ProfileAdvanced', '/profile/advanced', 0, 4, '1.2.', 2, 0, '', 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (19, '成功', 'success', 'ResultSuccess', '/result/success', 0, 3, '1.2.', 2, 0, '', 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (20, '失败', 'fail', 'ResultFail', '/result/fail', 0, 3, '1.2.', 2, 0, '', 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (21, '403', '403', 'Exception403', '/exception/403', 0, 7, '1.2.', 2, 0, '', 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (22, '404', '404', 'Exception404', '/exception/404', 0, 7, '1.2.', 2, 0, '', 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (23, '500', '500', 'Exception500', '/exception/500', 0, 7, '1.2.', 2, 0, '', 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (24, '个人中心', 'center', 'AccountCenter', '/account/center', 0, 2, '1.2.', 2, 0, '', 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (25, '个人设置', 'settings', 'AccountSettings', '/account/settings', 1, 2, '1.2.', 2, 0, '', 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (26, '搜索列表（项目）', 'project', 'SearchProjects', '/list/search/project', 0, 16, '1.2.', 2, 0, '', 1, '2020-12-24 16:03:23', '2020-12-24 16:03:23', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (27, '搜索列表（应用）', 'application', 'SearchApplications', '/list/search/application', 0, 16, '1.2.', 2, 0, '', 1, '2020-12-24 16:03:23', '2020-12-24 16:03:23', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (9, '分析页', 'Analysis', 'Analysis', '/dashboard/analysis/:pageNo([1-9]\\\\d*)?', 0, 6, '1.2.', 2, 101, '', 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (8, '工作台', 'workplace', 'Workplace', '/dashboard/workplace', 0, 6, '1.2.', 2, 102, '', 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (36, 'IconSelector', 'TestIconSelect', 'EditList', '/other/icon-selector', 0, 35, '1.2.', 2, 810, 'tool', 1, '2020-12-25 17:23:15', '2020-12-25 17:23:15', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (37, '业务布局', 'bizLayout', 'RouteView', '', 0, 35, '1.2.', 2, 820, 'layout', 1, '2020-12-25 17:23:20', '2020-12-25 17:23:20', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (6, '仪表盘', 'dashboard', 'RouteView', '', 0, 0, '1.', 1, 100, 'dashboard', 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (1, '表单页', 'form', 'RouteView', '', 0, 0, '1.', 1, 200, 'form', 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (5, '列表页', 'list', 'RouteView', '', 0, 0, '1.', 1, 300, 'table', 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (4, '详情页', 'profile', 'RouteView', '', 0, 0, '1.', 1, 400, 'profile', 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (3, '结果页', 'result', 'PageView', '', 0, 0, '1.', 1, 500, 'check-circle-o', 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (7, '异常页', 'exception', 'RouteView', '', 0, 0, '1.', 1, 600, 'warning', 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (2, '个人页', 'account', 'RouteView', '', 0, 0, '1.', 1, 700, 'user', 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_route (id, name, code, component, path, hide_children, pid, level_path, level, sequence, icon, status, gmt_create, gmt_modified, creator, modifier) VALUES (35, '其他组件', 'other', 'PageView', '', 0, 0, '1.', 1, 800, 'slack', 1, '2020-12-25 17:23:07', '2020-12-25 17:23:07', -1, -1);

drop table if exists upms_permission;
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (1, 'FR00001', 'FRONT_ROUTE', 1, 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (2, 'FR00002', 'FRONT_ROUTE', 2, 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (3, 'FR00003', 'FRONT_ROUTE', 3, 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (4, 'FR00004', 'FRONT_ROUTE', 4, 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (5, 'FR00005', 'FRONT_ROUTE', 5, 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (6, 'FR00006', 'FRONT_ROUTE', 6, 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (7, 'FR00007', 'FRONT_ROUTE', 7, 1, '2020-12-24 15:49:19', '2020-12-24 15:49:19', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (8, 'FR00008', 'FRONT_ROUTE', 8, 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (9, 'FR00009', 'FRONT_ROUTE', 9, 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (10, 'FR00010', 'FRONT_ROUTE', 10, 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (11, 'FR00011', 'FRONT_ROUTE', 11, 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (12, 'FR00012', 'FRONT_ROUTE', 12, 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (13, 'FR00013', 'FRONT_ROUTE', 13, 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (14, 'FR00014', 'FRONT_ROUTE', 14, 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (15, 'FR00015', 'FRONT_ROUTE', 15, 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (16, 'FR00016', 'FRONT_ROUTE', 16, 1, '2020-12-24 15:58:43', '2020-12-24 15:58:43', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (17, 'FR00017', 'FRONT_ROUTE', 17, 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (18, 'FR00018', 'FRONT_ROUTE', 18, 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (19, 'FR00019', 'FRONT_ROUTE', 19, 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (20, 'FR00020', 'FRONT_ROUTE', 20, 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (21, 'FR00021', 'FRONT_ROUTE', 21, 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (22, 'FR00022', 'FRONT_ROUTE', 22, 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (23, 'FR00023', 'FRONT_ROUTE', 23, 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (24, 'FR00024', 'FRONT_ROUTE', 24, 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (25, 'FR00025', 'FRONT_ROUTE', 25, 1, '2020-12-24 16:02:53', '2020-12-24 16:02:53', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (26, 'FR00026', 'FRONT_ROUTE', 26, 1, '2020-12-24 16:03:23', '2020-12-24 16:03:23', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (27, 'FR00027', 'FRONT_ROUTE', 27, 1, '2020-12-24 16:03:23', '2020-12-24 16:03:23', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (28, 'FR00028', 'FRONT_ROUTE', 28, 1, '2020-12-24 16:13:50', '2020-12-24 16:13:50', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (29, 'FR00029', 'FRONT_ROUTE', 29, 1, '2020-12-24 16:13:50', '2020-12-24 16:13:50', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (30, 'FR00030', 'FRONT_ROUTE', 30, 1, '2020-12-24 16:13:50', '2020-12-24 16:13:50', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (31, 'FR00031', 'FRONT_ROUTE', 31, 1, '2020-12-24 16:13:50', '2020-12-24 16:13:50', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (32, 'FR00032', 'FRONT_ROUTE', 32, 1, '2020-12-24 16:13:50', '2020-12-24 16:13:50', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (33, 'FR00033', 'FRONT_ROUTE', 33, 1, '2020-12-24 18:28:38', '2020-12-24 18:28:38', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (34, 'FR00035', 'FRONT_ROUTE', 35, 1, '2020-12-25 17:23:07', '2020-12-25 17:23:07', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (35, 'FR00036', 'FRONT_ROUTE', 36, 1, '2020-12-25 17:23:15', '2020-12-25 17:23:15', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (36, 'FR00037', 'FRONT_ROUTE', 37, 1, '2020-12-25 17:23:20', '2020-12-25 17:23:20', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (37, 'FR00038', 'FRONT_ROUTE', 38, 1, '2020-12-25 17:23:24', '2020-12-25 17:23:24', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (38, 'FR00039', 'FRONT_ROUTE', 39, 1, '2020-12-25 17:23:25', '2020-12-25 17:23:25', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (39, 'FR00040', 'FRONT_ROUTE', 40, 1, '2020-12-25 17:23:25', '2020-12-25 17:23:25', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (40, 'FR00041', 'FRONT_ROUTE', 41, 1, '2020-12-25 17:23:25', '2020-12-25 17:23:25', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (41, 'FR00042', 'FRONT_ROUTE', 42, 1, '2020-12-25 17:23:25', '2020-12-25 17:23:25', -1, -1);
INSERT INTO kt.upms_permission (id, code, type, resource_id, status, gmt_create, gmt_modified, creator, modifier) VALUES (42, 'FR00043', 'FRONT_ROUTE', 43, 1, '2020-12-25 17:23:25', '2020-12-25 17:23:25', -1, -1);