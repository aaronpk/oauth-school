CREATE TABLE `issuers` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `uri` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `scopes` varchar(255) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `last_logged_in_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `results` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `issuer_id` int(11) DEFAULT NULL,
  `test` varchar(20) DEFAULT NULL,
  `success` tinyint(4) DEFAULT NULL,
  `message` text,
  `data` longtext,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `challenge_participants` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `issuer` varchar(255) DEFAULT NULL,
  `complete` tinyint(4) DEFAULT NULL,
  `status_active` tinyint(4) DEFAULT NULL,
  `status_issued_before` tinyint(4) DEFAULT NULL,
  `status_confidential` tinyint(4) DEFAULT NULL,
  `status_lifetime` tinyint(4) DEFAULT NULL,
  `status_scope` tinyint(4) DEFAULT NULL,
  `status_custom_claim` tinyint(4) DEFAULT NULL,
  `attempts` int(11) DEFAULT NULL,
  `claims` longtext DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `challenge_winners` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `participant_id` int(11) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  `prize` varchar(255) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
