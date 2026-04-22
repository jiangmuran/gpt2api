-- +goose Up
-- +goose StatementBegin

-- 1) credit_transactions 增加 actor_user_id,用于管理员调账的审计与 24h 日累计限额。
ALTER TABLE `credit_transactions`
    ADD COLUMN `actor_user_id` BIGINT UNSIGNED NOT NULL DEFAULT 0
        COMMENT '执行此笔流水的管理员 user_id;0 表示系统/自助' AFTER `remark`,
    ADD KEY `idx_actor_created` (`actor_user_id`, `created_at`);

-- 2) users 增加 token_version,用于让旧 JWT 在密码/角色/状态变更后立即失效。
ALTER TABLE `users`
    ADD COLUMN `token_version` BIGINT UNSIGNED NOT NULL DEFAULT 1
        COMMENT '令牌版本号;JWT claim.tv 不匹配时视作失效' AFTER `version`;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE `credit_transactions`
    DROP INDEX `idx_actor_created`,
    DROP COLUMN `actor_user_id`;

ALTER TABLE `users`
    DROP COLUMN `token_version`;

-- +goose StatementEnd
