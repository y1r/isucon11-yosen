DROP TABLE IF EXISTS `isu_association_config`;
DROP TABLE IF EXISTS `isu_condition`;
DROP TABLE IF EXISTS `isu`;
DROP TABLE IF EXISTS `user`;

CREATE TABLE `isu` (
  `id` bigint AUTO_INCREMENT,
  `jia_isu_uuid` CHAR(36) NOT NULL UNIQUE,
  `name` VARCHAR(255) NOT NULL,
  `image` LONGBLOB,
  `character` VARCHAR(255),
  `jia_user_id` VARCHAR(255) NOT NULL,
  `created_at` DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
   PRIMARY KEY(`id`)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

CREATE TABLE `isu_condition` (
  `id` bigint DEFAULT 1,
  `jia_isu_uuid` CHAR(36) NOT NULL,
  `timestamp` DATETIME NOT NULL,
  `is_sitting` TINYINT(1) NOT NULL,
  `condition` VARCHAR(255) NOT NULL,
  `message` VARCHAR(255) NOT NULL,
  `created_at` DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
  is_dirty TINYINT(1) AS (`condition` LIKE '%is_dirty=true%') STORED,
  is_overweight TINYINT(1) AS (`condition` LIKE '%is_overweight=true%') STORED,
  is_broken TINYINT(1) AS (`condition` LIKE '%is_broken=true%') STORED,
  bad_count INT AS (is_dirty + is_overweight + is_broken) STORED,
  bad_name VARCHAR(10) AS (
    CASE WHEN bad_count = 0 THEN 'info'
         WHEN bad_count = 3 THEN 'critical'
                            ELSE 'warning'
    END
  ) STORED,
  PRIMARY KEY (jia_isu_uuid, `timestamp`),
  INDEX idx_uuid_createdat(jia_isu_uuid, created_at)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

CREATE TABLE `user` (
  `jia_user_id` VARCHAR(255) PRIMARY KEY,
  `created_at` DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

CREATE TABLE `isu_association_config` (
  `name` VARCHAR(255) PRIMARY KEY,
  `url` VARCHAR(255) NOT NULL UNIQUE
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;
