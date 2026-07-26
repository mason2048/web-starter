ALTER TABLE sys_user
    ADD COLUMN security_epoch BIGINT NOT NULL DEFAULT 0 AFTER status,
    ADD COLUMN password_changed_at DATETIME(6) NULL AFTER security_epoch;

ALTER TABLE sec_service_account
    ADD COLUMN security_epoch BIGINT NOT NULL DEFAULT 0 AFTER enabled,
    ADD COLUMN disabled_at DATETIME(6) NULL AFTER security_epoch;

ALTER TABLE sec_access_credential
    ADD COLUMN subject_security_epoch BIGINT NOT NULL DEFAULT 0 AFTER subject_id,
    ADD COLUMN revoked_reason VARCHAR(64) NULL AFTER revoked_at;

-- Credentials issued before this migration must never revive when an already-disabled
-- identity is enabled later. Enabled identities remain on epoch 0 for rolling compatibility.
UPDATE sys_user
   SET security_epoch = 1
 WHERE status <> 'ENABLED';

UPDATE sec_service_account
   SET security_epoch = 1,
       disabled_at = updated_at
 WHERE enabled = FALSE;
