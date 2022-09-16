
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `certificateStatus` DROP COLUMN `LockCol`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `certificateStatus` ADD COLUMN `LockCol` BIGINT(20) DEFAULT 0;
