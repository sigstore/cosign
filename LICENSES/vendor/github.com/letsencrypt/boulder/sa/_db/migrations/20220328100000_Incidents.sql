-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `incidents` (
    `id` bigint(20) NOT NULL AUTO_INCREMENT,
    `serialTable` varchar(128) NOT NULL,
    `url` varchar(1024) NOT NULL,
    `renewBy` datetime NOT NULL,
    `enabled` boolean DEFAULT false,
    PRIMARY KEY (`id`)
) CHARSET=utf8mb4;

CREATE TABLE `incident_foo` (
    `serial` varchar(255) NOT NULL,
    `registrationID` bigint(20) unsigned NULL,
    `orderID` bigint(20) unsigned NULL,
    `lastNoticeSent` datetime NULL,
    PRIMARY KEY (`serial`),
    KEY `registrationID_idx` (`registrationID`),
    KEY `orderID_idx` (`orderID`)
) CHARSET=utf8mb4;

CREATE TABLE `incident_bar` (
    `serial` varchar(255) NOT NULL,
    `registrationID` bigint(20) unsigned NULL,
    `orderID` bigint(20) unsigned NULL,
    `lastNoticeSent` datetime NULL,
    PRIMARY KEY (`serial`),
    KEY `registrationID_idx` (`registrationID`),
    KEY `orderID_idx` (`orderID`)
) CHARSET=utf8mb4;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `incidents`
DROP TABLE `incident_foo`
DROP TABLE `incident_bar`
