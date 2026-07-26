ALTER TABLE sys_mcp_call_log
    ADD COLUMN idempotency_key_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER error_code,
    ADD COLUMN replayed BOOLEAN NOT NULL DEFAULT FALSE AFTER idempotency_key_hash,
    ADD KEY idx_sys_mcp_call_log_idempotency (idempotency_key_hash, created_at);
