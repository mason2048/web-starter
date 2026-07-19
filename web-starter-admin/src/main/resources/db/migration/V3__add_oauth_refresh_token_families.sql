CREATE TABLE sec_oauth_refresh_family (
    authorization_id VARCHAR(100) NOT NULL,
    current_token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    generation BIGINT NOT NULL,
    current_issued_at DATETIME(6) NOT NULL,
    current_expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    revoke_reason VARCHAR(100) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (authorization_id),
    UNIQUE KEY uk_sec_oauth_refresh_family_current_hash (current_token_hash),
    KEY idx_sec_oauth_refresh_family_expiry (revoked_at, current_expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sec_oauth_refresh_history (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    authorization_id VARCHAR(100) NOT NULL,
    generation BIGINT NOT NULL,
    issued_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    consumed_at DATETIME(6) NULL,
    revoked_at DATETIME(6) NULL,
    revoke_reason VARCHAR(100) NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (token_hash),
    UNIQUE KEY uk_sec_oauth_refresh_history_generation (authorization_id, generation),
    KEY idx_sec_oauth_refresh_history_expiry (authorization_id, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Refresh tokens created before token-family tracking cannot provide reliable reuse
-- detection. Fail closed by requiring those clients to authorize again. Existing
-- short-lived access tokens remain governed by sec_oauth_token_registry.
UPDATE oauth2_authorization
   SET refresh_token_value = NULL,
       refresh_token_issued_at = NULL,
       refresh_token_expires_at = NULL,
       refresh_token_metadata = NULL
 WHERE refresh_token_value IS NOT NULL;
