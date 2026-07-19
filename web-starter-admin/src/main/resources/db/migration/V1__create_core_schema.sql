CREATE TABLE sys_user (
    id BIGINT NOT NULL,
    username VARCHAR(64) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(200) NULL,
    mobile VARCHAR(32) NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ENABLED',
    version INT NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    deleted TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_sys_user_username (username),
    KEY idx_sys_user_status (status, deleted, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sys_role (
    id BIGINT NOT NULL,
    code VARCHAR(64) NOT NULL,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(500) NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ENABLED',
    version INT NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    deleted TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_sys_role_code (code),
    KEY idx_sys_role_status (status, deleted, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sys_permission (
    id BIGINT NOT NULL,
    code VARCHAR(128) NOT NULL,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(32) NOT NULL,
    description VARCHAR(500) NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ENABLED',
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    deleted TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_sys_permission_code (code),
    KEY idx_sys_permission_status (status, deleted, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sys_menu (
    id BIGINT NOT NULL,
    parent_id BIGINT NULL,
    name VARCHAR(100) NOT NULL,
    path VARCHAR(255) NULL,
    component VARCHAR(255) NULL,
    icon VARCHAR(64) NULL,
    sort_order INT NOT NULL DEFAULT 0,
    visible BOOLEAN NOT NULL DEFAULT TRUE,
    status VARCHAR(20) NOT NULL DEFAULT 'ENABLED',
    permission_code VARCHAR(128) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    deleted TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_sys_menu_parent_sort (parent_id, sort_order, deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sys_config (
    id BIGINT NOT NULL,
    config_key VARCHAR(128) NOT NULL,
    config_value TEXT NOT NULL,
    value_type VARCHAR(32) NOT NULL,
    description VARCHAR(500) NULL,
    builtin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    deleted TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_sys_config_key (config_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sys_user_role (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    KEY idx_sys_user_role_role (role_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sys_role_permission (
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    KEY idx_sys_role_permission_permission (permission_id, role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sys_role_menu (
    role_id BIGINT NOT NULL,
    menu_id BIGINT NOT NULL,
    PRIMARY KEY (role_id, menu_id),
    KEY idx_sys_role_menu_menu (menu_id, role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sys_login_log (
    id BIGINT NOT NULL,
    username VARCHAR(64) NOT NULL,
    result VARCHAR(20) NOT NULL,
    failure_reason VARCHAR(500) NULL,
    ip_address VARCHAR(64) NULL,
    user_agent VARCHAR(500) NULL,
    trace_id VARCHAR(64) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    deleted TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_sys_login_log_created (created_at, id),
    KEY idx_sys_login_log_username (username, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sys_operation_log (
    id BIGINT NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    actor_id VARCHAR(128) NULL,
    actor_name VARCHAR(100) NULL,
    module VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64) NULL,
    resource_id VARCHAR(128) NULL,
    result VARCHAR(20) NOT NULL,
    request_method VARCHAR(16) NULL,
    request_path VARCHAR(500) NULL,
    ip_address VARCHAR(64) NULL,
    duration_ms BIGINT NULL,
    detail_json TEXT NULL,
    trace_id VARCHAR(64) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    deleted TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_sys_operation_log_created (created_at, id),
    KEY idx_sys_operation_log_actor (actor_type, actor_id, created_at),
    KEY idx_sys_operation_log_trace (trace_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sys_mcp_call_log (
    id BIGINT NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    actor_id VARCHAR(128) NULL,
    actor_name VARCHAR(100) NULL,
    token_id VARCHAR(128) NULL,
    client_id VARCHAR(128) NULL,
    tool_name VARCHAR(128) NOT NULL,
    permission_code VARCHAR(128) NULL,
    result VARCHAR(20) NOT NULL,
    duration_ms BIGINT NULL,
    ip_address VARCHAR(64) NULL,
    error_code VARCHAR(64) NULL,
    trace_id VARCHAR(64) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    deleted TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_sys_mcp_call_log_created (created_at, id),
    KEY idx_sys_mcp_call_log_actor (actor_type, actor_id, created_at),
    KEY idx_sys_mcp_call_log_tool (tool_name, created_at),
    KEY idx_sys_mcp_call_log_trace (trace_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE biz_project (
    id BIGINT NOT NULL,
    name VARCHAR(120) NOT NULL,
    code VARCHAR(64) NOT NULL,
    owner_id BIGINT NOT NULL,
    owner_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,
    description TEXT NULL,
    version INT NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    deleted TINYINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_biz_project_code (code),
    KEY idx_biz_project_status (status, deleted, id),
    KEY idx_biz_project_owner (owner_id, deleted, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sec_service_account (
    id BIGINT NOT NULL,
    code VARCHAR(64) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description VARCHAR(500) NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    role_ids VARCHAR(2000) NOT NULL,
    created_by BIGINT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_by BIGINT NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_sec_service_account_code (code),
    KEY idx_sec_service_account_enabled (enabled, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sec_access_credential (
    id BIGINT NOT NULL,
    credential_type VARCHAR(32) NOT NULL,
    subject_id BIGINT NOT NULL,
    name VARCHAR(100) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    token_hint VARCHAR(32) NOT NULL,
    scopes VARCHAR(4000) NOT NULL,
    ip_cidrs VARCHAR(2000) NULL,
    expires_at DATETIME(6) NULL,
    revoked_at DATETIME(6) NULL,
    last_used_at DATETIME(6) NULL,
    created_by BIGINT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_sec_access_credential_hash (token_hash),
    KEY idx_sec_access_credential_subject (credential_type, subject_id, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sec_oauth_client (
    id VARCHAR(100) NOT NULL,
    client_id VARCHAR(128) NOT NULL,
    client_secret_hash VARCHAR(255) NULL,
    client_name VARCHAR(100) NOT NULL,
    authentication_methods VARCHAR(1000) NOT NULL,
    grant_types VARCHAR(1000) NOT NULL,
    redirect_uris TEXT NULL,
    scopes VARCHAR(4000) NOT NULL,
    require_consent BOOLEAN NOT NULL DEFAULT TRUE,
    require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
    service_account_id BIGINT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_sec_oauth_client_client_id (client_id),
    KEY idx_sec_oauth_client_service (service_account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sec_oauth_token_registry (
    id BIGINT NOT NULL,
    jti_hash CHAR(64) NOT NULL,
    authorization_id VARCHAR(100) NOT NULL,
    token_type VARCHAR(32) NOT NULL,
    subject_type VARCHAR(32) NULL,
    subject_id BIGINT NULL,
    principal_name VARCHAR(200) NOT NULL,
    client_id VARCHAR(128) NOT NULL,
    scopes VARCHAR(4000) NOT NULL,
    issued_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_sec_oauth_token_registry_jti (jti_hash),
    KEY idx_sec_oauth_token_registry_authorization (authorization_id),
    KEY idx_sec_oauth_token_registry_subject (subject_type, subject_id, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE oauth2_authorization (
    id VARCHAR(100) NOT NULL,
    registered_client_id VARCHAR(100) NOT NULL,
    principal_name VARCHAR(200) NOT NULL,
    authorization_grant_type VARCHAR(100) NOT NULL,
    authorized_scopes VARCHAR(1000) NULL,
    attributes BLOB NULL,
    state VARCHAR(500) NULL,
    authorization_code_value BLOB NULL,
    authorization_code_issued_at TIMESTAMP(6) NULL,
    authorization_code_expires_at TIMESTAMP(6) NULL,
    authorization_code_metadata BLOB NULL,
    access_token_value BLOB NULL,
    access_token_issued_at TIMESTAMP(6) NULL,
    access_token_expires_at TIMESTAMP(6) NULL,
    access_token_metadata BLOB NULL,
    access_token_type VARCHAR(100) NULL,
    access_token_scopes VARCHAR(1000) NULL,
    oidc_id_token_value BLOB NULL,
    oidc_id_token_issued_at TIMESTAMP(6) NULL,
    oidc_id_token_expires_at TIMESTAMP(6) NULL,
    oidc_id_token_metadata BLOB NULL,
    refresh_token_value BLOB NULL,
    refresh_token_issued_at TIMESTAMP(6) NULL,
    refresh_token_expires_at TIMESTAMP(6) NULL,
    refresh_token_metadata BLOB NULL,
    user_code_value BLOB NULL,
    user_code_issued_at TIMESTAMP(6) NULL,
    user_code_expires_at TIMESTAMP(6) NULL,
    user_code_metadata BLOB NULL,
    device_code_value BLOB NULL,
    device_code_issued_at TIMESTAMP(6) NULL,
    device_code_expires_at TIMESTAMP(6) NULL,
    device_code_metadata BLOB NULL,
    PRIMARY KEY (id),
    KEY idx_oauth2_authorization_registered_client (registered_client_id),
    KEY idx_oauth2_authorization_principal (principal_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE oauth2_authorization_consent (
    registered_client_id VARCHAR(100) NOT NULL,
    principal_name VARCHAR(200) NOT NULL,
    authorities VARCHAR(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
