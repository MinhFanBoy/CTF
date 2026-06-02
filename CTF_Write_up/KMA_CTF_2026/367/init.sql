

CREATE DATABASE IF NOT EXISTS document;
USE document;


CREATE TABLE IF NOT EXISTS document (
    title VARCHAR(255),
    content VARCHAR(1000),
    filename VARCHAR(255)
);


CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS user_meta (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    meta_key VARCHAR(64) NOT NULL,
    meta_value LONGTEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY user_meta_unique (user_id, meta_key)
);


CREATE TABLE IF NOT EXISTS flag (
    flag VARCHAR(255) NOT NULL
);


INSERT INTO document (title, content, filename)
VALUES ('TOP SECRET DOCUMENT', '', '655f365d59872.png');

INSERT INTO flag (flag) VALUES ('KMACTF{fake_flag_for_testing}');

CREATE USER 'fake'@'%' IDENTIFIED BY 'fake';
GRANT ALL PRIVILEGES ON *.* TO 'fake'@'%';
FLUSH PRIVILEGES;

