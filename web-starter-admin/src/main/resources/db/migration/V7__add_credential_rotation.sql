ALTER TABLE sec_access_credential
    ADD COLUMN pepper_version VARCHAR(32) NOT NULL DEFAULT 'v1' AFTER token_hash,
    ADD KEY idx_sec_access_credential_pepper_hash (pepper_version, token_hash);

ALTER TABLE sec_oauth_client
    MODIFY COLUMN client_secret_hash VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN client_secret_version VARCHAR(32) NULL AFTER client_secret_hash,
    ADD COLUMN retiring_client_secret_hash VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER client_secret_version,
    ADD COLUMN retiring_client_secret_version VARCHAR(32) NULL AFTER retiring_client_secret_hash,
    ADD COLUMN retiring_client_secret_expires_at DATETIME(6) NULL AFTER retiring_client_secret_version,
    ADD COLUMN client_secret_rotated_at DATETIME(6) NULL AFTER retiring_client_secret_expires_at,
    ADD KEY idx_sec_oauth_client_retiring_secret_expiry (retiring_client_secret_expires_at);

UPDATE sec_oauth_client
   SET client_secret_version = 'v1'
 WHERE client_secret_hash IS NOT NULL
   AND client_secret_version IS NULL;
