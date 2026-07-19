INSERT INTO sys_role
    (id, code, name, description, status, version, created_at, updated_at, deleted)
VALUES
    (1, 'ADMIN', '系统管理员', '拥有脚手架内全部管理权限', 'ENABLED', 0,
     CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0);

INSERT INTO sys_permission
    (id, code, name, type, description, status, created_at, updated_at, deleted)
VALUES
    (1000, 'system:info', '查看系统信息', 'MCP', '读取非敏感产品与运行时信息', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1001, 'system:user:list', '查看用户', 'API', '查询用户和用户详情', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1002, 'system:user:create', '创建用户', 'API', '创建后台用户', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1003, 'system:user:update', '更新用户', 'API', '更新用户资料与密码', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1004, 'system:user:remove', '删除用户', 'API', '逻辑删除用户', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1011, 'system:role:list', '查看角色', 'API', '查询角色和授权关系', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1012, 'system:role:create', '创建角色', 'API', '创建角色并分配权限', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1013, 'system:role:update', '更新角色', 'API', '更新角色和授权关系', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1014, 'system:role:remove', '删除角色', 'API', '逻辑删除角色', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1021, 'system:permission:list', '查看权限', 'API', '查询权限字典', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1022, 'system:permission:manage', '管理权限', 'API', '维护权限字典', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1031, 'system:menu:list', '查看菜单', 'API', '查询菜单与按钮定义', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1032, 'system:menu:manage', '管理菜单', 'API', '维护菜单与按钮定义', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1041, 'system:config:list', '查看配置', 'API', '查询非敏感系统配置', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1042, 'system:config:manage', '管理配置', 'API', '维护非敏感系统配置', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1051, 'audit:list', '查看审计日志', 'API', '查询登录、操作和 MCP 调用日志', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1101, 'project:list', '查看项目', 'API', '查询示例项目', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1102, 'project:create', '创建项目', 'API', '创建示例项目', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1103, 'project:update', '更新项目', 'API', '更新示例项目', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1104, 'project:remove', '删除项目', 'API', '逻辑删除示例项目', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1201, 'security:personal-token:list', '查看个人令牌', 'API', '查看本人令牌元数据', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1202, 'security:personal-token:create', '创建个人令牌', 'API', '签发一次性展示的个人访问令牌', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1203, 'security:personal-token:revoke', '吊销个人令牌', 'API', '吊销本人个人访问令牌', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1211, 'security:service-account:manage', '管理服务账号', 'API', '维护服务账号及其令牌', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (1221, 'security:oauth-client:manage', '管理 OAuth 客户端', 'API', '维护外部 Agent 使用的 OAuth 客户端', 'ENABLED', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0);

INSERT INTO sys_role_permission (role_id, permission_id)
SELECT 1, id FROM sys_permission WHERE deleted = 0;

INSERT INTO sys_menu
    (id, parent_id, name, path, component, icon, sort_order, visible, status,
     permission_code, created_at, updated_at, deleted)
VALUES
    (2001, NULL, '工作台', '/overview', 'OverviewView', 'DataBoard', 10, TRUE, 'ENABLED', NULL, CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2002, NULL, '项目管理', '/projects', 'ProjectsView', 'FolderOpened', 20, TRUE, 'ENABLED', 'project:list', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2010, NULL, '系统管理', NULL, NULL, 'Setting', 30, TRUE, 'ENABLED', NULL, CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2011, 2010, '用户管理', '/users', 'UsersView', 'User', 10, TRUE, 'ENABLED', 'system:user:list', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2012, 2010, '角色管理', '/roles', 'RolesView', 'UserFilled', 20, TRUE, 'ENABLED', 'system:role:list', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2013, 2010, '菜单管理', '/menus', 'MenusView', 'Menu', 30, TRUE, 'ENABLED', 'system:menu:list', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2014, 2010, '系统配置', '/configs', 'ConfigsView', 'Tools', 40, TRUE, 'ENABLED', 'system:config:list', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2020, NULL, '审计日志', NULL, NULL, 'Document', 40, TRUE, 'ENABLED', 'audit:list', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2021, 2020, '登录日志', '/logs/login', 'LoginLogsView', 'Key', 10, TRUE, 'ENABLED', 'audit:list', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2022, 2020, '操作日志', '/logs/operation', 'OperationLogsView', 'Tickets', 20, TRUE, 'ENABLED', 'audit:list', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2023, 2020, 'MCP 调用日志', '/logs/mcp', 'McpLogsView', 'Connection', 30, TRUE, 'ENABLED', 'audit:list', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2030, NULL, '安全管理', NULL, NULL, 'Lock', 50, TRUE, 'ENABLED', NULL, CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2031, 2030, '个人访问令牌', '/security/personal-tokens', 'PersonalTokensView', 'Key', 10, TRUE, 'ENABLED', 'security:personal-token:list', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2032, 2030, '服务账号', '/security/service-accounts', 'ServiceAccountsView', 'Avatar', 20, TRUE, 'ENABLED', 'security:service-account:manage', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (2033, 2030, 'OAuth 客户端', '/security/oauth-clients', 'OAuthClientsView', 'Link', 30, TRUE, 'ENABLED', 'security:oauth-client:manage', CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0);

INSERT INTO sys_role_menu (role_id, menu_id)
SELECT 1, id FROM sys_menu WHERE deleted = 0;

INSERT INTO sys_config
    (id, config_key, config_value, value_type, description, builtin,
     created_at, updated_at, deleted)
VALUES
    (3001, 'app.display-name', '启程 Web Starter', 'STRING', '管理端显示名称', TRUE, CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (3002, 'project.default-status', 'PLANNING', 'STRING', '示例项目的默认状态', TRUE, CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0),
    (3003, 'audit.retention-days', '180', 'INTEGER', '审计日志建议保留天数', TRUE, CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), 0);
