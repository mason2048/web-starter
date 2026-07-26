CREATE TABLE mcp_idempotency_record (
    id BIGINT NOT NULL,
    namespace_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    tool_name VARCHAR(128) NOT NULL,
    idempotency_key_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    reservation_nonce CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(20) NOT NULL,
    response_json JSON NULL,
    resource_id VARCHAR(128) NULL,
    created_at DATETIME(6) NOT NULL,
    completed_at DATETIME(6) NULL,
    expires_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_mcp_idempotency_identity (namespace_hash, tool_name, idempotency_key_hash),
    KEY idx_mcp_idempotency_expiry (expires_at, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
