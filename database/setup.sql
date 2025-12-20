CREATE DATABASE IF NOT EXISTS auth_demo
  CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE auth_demo;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(150) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  failed_count INT DEFAULT 0,
  locked_until DATETIME NULL,
  fingerprint_pin VARCHAR(20) NULL
);

CREATE TABLE IF NOT EXISTS stylometry (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  avg_word_len DOUBLE,
  uniq_word_ratio DOUBLE,
  avg_sent_len DOUBLE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS login_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  username_attempted VARCHAR(150),
  success BOOLEAN,
  ip VARCHAR(45),
  reason VARCHAR(255),
  ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS security_events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(50) NOT NULL,
  username VARCHAR(100),
  ip VARCHAR(45),
  details TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);