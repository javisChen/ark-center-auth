# 运行

## Docker Build
```shell
docker build -f ./ark-center-auth-start/Dockerfile -t ark-center-auth:v1 ./ark-center-auth-start
```
## Docker Run
```shell
docker run -p 8080:8080 --name ark-center-auth -d \
-e NACOS_DISCOVERY_IP=172.24.80.20 \
-e DISCOVERY_SERVER_ADDR=172.24.80.20:8848 \
-e NACOS_CONFIG_SERVER_ADDR=172.24.80.20:8848 \
-e SYS_OPT=-DSpring.profiles.active=dev \
ark-center-auth:v1
```
# 作用

基于RBAC（Role-Based Access Control）模型下沉的通用权限体系系统，可满足98%的Web应用系统。 整体围绕着用户、角色、权限三个实体进行实现。控制粒度达到页面按钮级。

# 关键字
分布式、无感知、代码无入侵

# 目录结构

```
├── asserts         -- 项目资源（sql等）
├── ark-center-auth-auth    -- 认证模块
├── ark-center-auth-web     -- 权限系统运行模块
└── pom.xml

```

# 系统设计简述

# 数据模型

## ER图

![](asserts/ark-center-auth-er.png)

## 表说明

| 表名  | 说明 |
| ----- | ---- |
| auth_user_group | 用户组表 |
| auth_user_group_user_rel | 用户组与用户关联表 |
| auth_user_group_role_rel | 用户组与角色关联表 |
| auth_user | 用户表 |
| auth_role | 角色表 |
| auth_user_role_rel | 用户角色关联表 |
| auth_permission | 权限表 |
| auth_permission_role_rel | 角色与权限联表 |
| auth_route | 前端路由表 |
| auth_element | 页面元素表 |
| auth_api | api表 |
| auth_application | 应用表 |

# 主要技术选型

## 后端

| 组件  | 说明 |
| ----- | ---- |
| SpringBoot | web框架 |
| MybatisPlus | 数据层 |
| Redis | 缓存中间件 |

## 前端

| 组件  | 说明 |
| ----- | ---- |
| Vue | 前端框架 |"# ark-center-auth" 
