-- =========================================================
-- CyberSOC: Production Cybersecurity Dashboard MySQL Schema
-- =========================================================

CREATE DATABASE IF NOT EXISTS `cyber_security_db` 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE `cyber_security_db`;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `email` VARCHAR(120) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `language_pref` VARCHAR(10) DEFAULT 'en',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_username` (`username`),
    INDEX `idx_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Scan History Table
CREATE TABLE IF NOT EXISTS `scan_history` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `tool_name` VARCHAR(50) NOT NULL,
    `target_input` TEXT NOT NULL,
    `result_json` LONGTEXT NOT NULL,
    `scanned_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_tool_name` (`tool_name`),
    INDEX `idx_scanned_at` (`scanned_at`),
    CONSTRAINT `fk_scan_user` 
        FOREIGN KEY (`user_id`) 
        REFERENCES `users` (`id`) 
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sample Seed Data (optional admin user, password: Admin@123456)
-- Bcrypt hash generated with 12 salt rounds
INSERT IGNORE INTO `users` (`id`, `username`, `email`, `password_hash`, `language_pref`)
VALUES (1, 'soc_admin', 'admin@soc.local', '$2b$12$e8E7gXyS4L4Xn5i0k0t/p.y7qf9Z7nC0m.e1c6b3l1t2d4f5g6h7i', 'en');
