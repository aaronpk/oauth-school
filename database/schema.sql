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
