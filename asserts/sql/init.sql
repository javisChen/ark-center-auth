create table if not exists auth.auth_api
(
    id                bigint unsigned auto_increment,
    application_id    bigint unsigned  default '0'               not null comment '应用id，关联upms_application.id',
    name              varchar(50)      default ''                not null comment 'API名称',
    url               varchar(128)     default ''                not null comment '接口地址',
    method            varchar(10)      default ''                not null comment 'Http Method 1-GET 2-POST 3-PUT 4-DELETE 5-PATCH',
    status            tinyint unsigned default '1'               not null comment '状态 1-已启用；2-已禁用；',
    category_id       bigint unsigned  default '0'               not null comment 'api分类id，关联api_category.id',
    auth_type         tinyint unsigned default '1'               not null comment '认证授权类型 1-无需认证授权 2-只需认证无需授权 3-需要认证和授权',
    has_path_variable tinyint unsigned default '0'               not null comment 'url是否包含路径参数，例： /user/{userId}/api/{apiId} 0-不包含 1-包含',
    gmt_modified      datetime         default CURRENT_TIMESTAMP not null,
    gmt_create        datetime         default CURRENT_TIMESTAMP not null,
    creator           bigint unsigned  default '0'               not null comment '创建人',
    modifier          bigint unsigned  default '0'               not null comment '更新人',
    is_deleted        bigint unsigned  default '0'               not null comment '删除标识 0-表示未删除 大于0-已删除',
    primary key (id, application_id),
    constraint uk_application_id_url_method
    unique (url, application_id, method)
    )
    comment 'api表' charset = utf8mb4;

create index fk_upms_api_category_idx
    on auth.auth_api (category_id);

create index idx_application_id
    on auth.auth_api (application_id, is_deleted);

create index idx_is_deleted
    on auth.auth_api (is_deleted);

create table if not exists auth.auth_api_category
(
    id             bigint unsigned auto_increment,
    application_id bigint unsigned default '0'               not null comment '应用id，关联upms_application.id',
    name           varchar(50)     default ''                not null comment 'API分类名称',
    gmt_modified   datetime        default CURRENT_TIMESTAMP not null,
    gmt_create     datetime        default CURRENT_TIMESTAMP not null,
    creator        bigint unsigned default '0'               not null comment '创建人',
    modifier       bigint unsigned default '0'               not null comment '更新人',
    is_deleted     bigint unsigned default '0'               not null comment '删除标识 0-表示未删除 大于0-已删除',
    primary key (id, application_id),
    constraint uk_name_application_id
    unique (application_id, name, is_deleted)
    )
    comment 'Api分类表' charset = utf8mb4;

create index idx_application_id
    on auth.auth_api_category (application_id, is_deleted);

create index idx_is_deleted
    on auth.auth_api_category (is_deleted);

create table if not exists auth.auth_application
(
    id           bigint unsigned auto_increment
    primary key,
    name         varchar(50)      default ''                not null comment '应用名称',
    code         varchar(50)      default ''                not null comment '应用编码',
    status       tinyint unsigned default '1'               not null comment '状态 1-已上线；2-已下线；',
    type         tinyint unsigned default '1'               not null comment '应用类型 1-业务系统（前后端）2-纯后台服务',
    gmt_modified datetime         default CURRENT_TIMESTAMP not null,
    gmt_create   datetime         default CURRENT_TIMESTAMP not null,
    creator      bigint unsigned  default '0'               not null comment '创建人',
    modifier     bigint unsigned  default '0'               not null comment '更新人',
    is_deleted   bigint unsigned  default '0'               not null comment '删除标识 0-表示未删除 大于0-已删除',
    constraint uk_code
    unique (code, is_deleted),
    constraint uk_name
    unique (name, is_deleted)
    )
    comment '应用表' charset = utf8mb4;

create index uk_is_deleted
    on auth.auth_application (is_deleted);

create table if not exists auth.auth_element
(
    id           bigint unsigned auto_increment comment 'id'
    primary key,
    route_id     bigint unsigned                            not null comment '所属菜单id，关联upms_menu.id',
    name         varchar(45)                                not null comment '元素名称',
    type         tinyint unsigned default '0'               not null comment '元素类型 1-按钮；2-层；',
    gmt_create   datetime         default CURRENT_TIMESTAMP not null comment '创建时间',
    gmt_modified datetime         default CURRENT_TIMESTAMP not null comment '修改时间',
    creator      bigint unsigned  default '0'               not null comment '创建人',
    modifier     bigint unsigned  default '0'               not null comment '更新人',
    is_deleted   bigint unsigned  default '0'               not null comment '删除标识 0-表示未删除 大于0-已删除'
    )
    comment '页面元素表' charset = utf8mb4;

create index idx_is_deleted
    on auth.auth_element (is_deleted);

create index idx_route_id
    on auth.auth_element (route_id);

create table if not exists auth.auth_permission
(
    id           bigint unsigned auto_increment comment 'id'
    primary key,
    code         varchar(45)                                not null comment '权限编码',
    type         varchar(25)                                not null comment '权限类型 FRONT_ROUTE-前端路由；PAGE_ELEMENT-页面元素；PAGE-页面；FILE-文件；SER_API-内部服务API；OPEN_API-开放API',
    resource_id  bigint unsigned  default '0'               not null comment '资源id',
    status       tinyint unsigned default '1'               not null comment '权限状态 1-已启用；2-已禁用；',
    gmt_create   datetime         default CURRENT_TIMESTAMP not null comment '创建时间',
    gmt_modified datetime         default CURRENT_TIMESTAMP not null comment '修改时间',
    creator      bigint unsigned  default '0'               not null comment '创建人',
    modifier     bigint unsigned  default '0'               not null comment '更新人',
    is_deleted   bigint unsigned  default '0'               not null comment '删除标识 0-表示未删除 大于0-已删除',
    constraint uk_code
    unique (code),
    constraint uk_type_resource_id
    unique (type, resource_id, gmt_create)
    )
    comment '权限表' charset = utf8mb4;

create index idx_is_deleted
    on auth.auth_permission (is_deleted);

create table if not exists auth.auth_permission_role_rel
(
    id            bigint unsigned auto_increment comment 'id'
    primary key,
    permission_id bigint unsigned                           not null comment '权限id，关联upms_permission.id',
    role_id       bigint unsigned                           not null comment '角色id，关联upms_role.id',
    gmt_create    datetime        default CURRENT_TIMESTAMP not null comment '创建时间',
    gmt_modified  datetime        default CURRENT_TIMESTAMP not null comment '修改时间',
    creator       bigint unsigned default '0'               not null comment '创建人',
    modifier      bigint unsigned default '0'               not null comment '更新人',
    constraint uk_permission_id_role_id
    unique (permission_id, role_id)
    )
    comment '角色与权限关联表' charset = utf8mb4;

create table if not exists auth.auth_role
(
    id           bigint unsigned auto_increment comment 'Id'
    primary key,
    name         varchar(45)                                not null comment '用户名称',
    code         varchar(32)      default ''                not null comment '角色编码',
    status       tinyint unsigned default '1'               not null comment '角色状态 1-已启用；2-已禁用；',
    gmt_create   datetime         default CURRENT_TIMESTAMP not null comment '创建时间',
    gmt_modified datetime         default CURRENT_TIMESTAMP not null comment '更新时间',
    creator      bigint unsigned  default '0'               not null comment '创建人',
    modifier     bigint unsigned  default '0'               not null comment '更新人',
    is_deleted   bigint unsigned  default '0'               not null comment '删除标识 1-表示删除；0-表示未删除',
    constraint uk_name
    unique (name, is_deleted)
    )
    comment '角色表' charset = utf8mb4;

create index idx_is_deleted
    on auth.auth_role (is_deleted);

create table if not exists auth.auth_route
(
    id             bigint unsigned auto_increment comment 'id',
    application_id bigint unsigned default '0'               not null comment '应用id，关联upms_application.id',
    name           varchar(45)                               not null comment '路由标题',
    code           varchar(64)     default ''                not null comment '路由编码',
    component      varchar(64)     default ''                not null comment '组件名',
    pid            bigint          default 0                 not null comment '父级路由id',
    level_path     varchar(45)     default ''                not null comment '路由层级路径，例如：0.1.2 代表该菜单是三级路由，上级路由的id是1,再上级的路由id是0',
    level          int                                       not null comment '路由层级',
    path           varchar(64)     default ''                not null comment '路由path',
    icon           varchar(64)     default ''                not null comment '图标',
    hide_children  tinyint(1)      default 0                 not null comment '是否隐藏子路由 0-否 1-是',
    type           tinyint(1)      default 1                 not null comment '路由类型 1：菜单路由 2：页面路由 3: 隐藏页面路由',
    sequence       int             default 0                 not null comment '排序序号',
    status         tinyint(1)      default 1                 not null comment '权限状态 1-已启用；2-已禁用；',
    gmt_create     datetime        default CURRENT_TIMESTAMP not null comment '创建时间',
    gmt_modified   datetime        default CURRENT_TIMESTAMP not null comment '修改时间',
    creator        bigint unsigned default '0'               not null comment '创建人',
    modifier       bigint unsigned default '0'               not null comment '更新人',
    is_deleted     bigint unsigned default '0'               not null comment '删除标识 0-表示未删除 大于0-已删除',
    primary key (id, application_id),
    constraint uk_code
    unique (code, is_deleted),
    constraint uk_name
    unique (name, is_deleted)
    )
    comment '路由表' charset = utf8mb4;

create index fk_idx_system_id
    on auth.auth_route (application_id);

create index idx_pid
    on auth.auth_route (pid);

create table if not exists auth.auth_user
(
    id           bigint unsigned auto_increment
    primary key,
    user_name    varchar(45)                                null comment '用户名',
    phone        char(11)                                   not null comment '手机号码',
    code         varchar(45)      default ''                not null comment '用户编码',
    password     varchar(64)                                not null comment '用户密码',
    status       tinyint unsigned default '1'               not null comment '用户状态：1-已启用；2-已禁用；',
    gmt_create   datetime         default CURRENT_TIMESTAMP not null comment '创建时间',
    gmt_modified datetime         default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP comment '更新时间',
    creator      bigint unsigned  default '0'               not null comment '创建人',
    modifier     bigint unsigned  default '0'               not null comment '更新人',
    is_deleted   bigint unsigned  default '0'               not null comment '删除标识 0-表示未删除 大于0-已删除',
    constraint uk_code
    unique (code, is_deleted),
    constraint uk_phone
    unique (phone, is_deleted)
    )
    comment '用户表' charset = utf8mb4;

create index idx_is_deleted
    on auth.auth_user (is_deleted);

create table if not exists auth.auth_user_group
(
    id           bigint unsigned auto_increment comment 'Id'
    primary key,
    pid          bigint unsigned  default '0'               not null comment '父用户组id，关联id',
    name         varchar(45)                                not null comment '用户组名称',
    level        int unsigned     default '1'               not null comment '用户组层级',
    level_path   varchar(45)      default ''                not null comment '部门层级',
    type         tinyint unsigned default '1'               not null comment '用户组类型 1-公司 2-部门',
    inherit_type tinyint unsigned default '0'               not null comment '继承类型 0-不继承 1-继承上级用户组 2-继承所有用户组',
    status       tinyint unsigned default '1'               not null comment '用户组状态：1-已启用；2-已禁用；',
    gmt_create   datetime         default CURRENT_TIMESTAMP null comment '创建时间',
    gmt_modified datetime         default CURRENT_TIMESTAMP null comment '更新时间',
    creator      bigint unsigned  default '0'               not null comment '创建人',
    modifier     bigint unsigned  default '0'               not null comment '更新人',
    is_deleted   bigint unsigned  default '0'               not null comment '删除标识 0-表示未删除 大于0-已删除',
    constraint uk_name
    unique (name)
    )
    comment '用户组表' charset = utf8mb4;

create index idx_is_deleted
    on auth.auth_user_group (is_deleted);

create index idx_pid
    on auth.auth_user_group (pid);

create table if not exists auth.auth_user_group_role_rel
(
    id            bigint unsigned auto_increment comment 'Id'
    primary key,
    user_group_id bigint unsigned                           not null comment '用户组id，关联upms_user_group.id',
    role_id       bigint unsigned default '1'               not null comment '角色id，关联upms_role.id',
    gmt_create    datetime        default CURRENT_TIMESTAMP not null comment '创建时间',
    gmt_modified  datetime        default CURRENT_TIMESTAMP not null comment '更新时间',
    creator       bigint unsigned default '0'               not null comment '创建人',
    modifier      bigint unsigned default '0'               not null comment '更新人',
    constraint uk_user_group_id_role_id
    unique (user_group_id, role_id)
    )
    comment '用户组与角色关联表' charset = utf8mb4;

create table if not exists auth.auth_user_group_user_rel
(
    id            bigint unsigned auto_increment comment 'Id'
    primary key,
    user_group_id bigint unsigned                           not null comment '用户组名称，关联upms_user_group.id',
    user_id       bigint unsigned default '1'               not null comment '用户id，关联upms_user_id',
    gmt_create    datetime        default CURRENT_TIMESTAMP not null comment '创建时间',
    gmt_modified  datetime        default CURRENT_TIMESTAMP not null comment '更新时间',
    creator       bigint unsigned default '0'               not null comment '创建人',
    modifier      bigint unsigned default '0'               not null comment '更新人',
    constraint uk_user_group_id_user_id
    unique (user_group_id, user_id)
    )
    comment '用户组与用户关联表' charset = utf8mb4;

create table if not exists auth.auth_user_role_rel
(
    id           bigint unsigned auto_increment comment 'Id'
    primary key,
    user_id      bigint unsigned                           not null comment '用户id，关联upms_role.id',
    role_id      bigint unsigned                           not null comment '角色id，关联upms_role.id',
    gmt_create   datetime        default CURRENT_TIMESTAMP not null comment '创建时间',
    gmt_modified datetime        default CURRENT_TIMESTAMP not null comment '更新时间',
    creator      bigint unsigned default '0'               not null comment '创建人',
    modifier     bigint unsigned default '0'               not null comment '更新人',
    constraint uk_user_id_role_id
    unique (user_id, role_id)
    )
    comment '用户角色关联表' charset = utf8mb4;

